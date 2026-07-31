"""DossierForge — multi-user OSINT dossier SaaS.

Authorized use only. Every dossier requires the user to attest that they are
authorized to investigate the target, and every recon action is written to an
audit trail. Dossiers are isolated per user account.
"""

import json
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from models import AuditLog, Dossier, DossierShare, Note, ScanJob, Tag, User, db
from modules.export import render_json, render_markdown
from modules.nmap import get_nmap_summary, get_open_ports, run_nmap_scan
from modules.osint import (
    check_breach_data,
    get_osint_summary,
    search_emails,
    search_github_info,
    search_social_media,
)
from modules.whois import get_whois_summary, run_whois

login_manager = LoginManager()
# Background worker for recon jobs. Small pool: recon is I/O-bound and we want
# the request thread to return immediately instead of blocking on a slow scan.
_scan_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")


def _normalize_db_uri(uri):
    # Heroku/older providers hand out postgres:// which SQLAlchemy no longer
    # accepts; normalize to postgresql://.
    if uri.startswith("postgres://"):
        return uri.replace("postgres://", "postgresql://", 1)
    return uri


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    default_db = "sqlite:///" + os.path.join(app.instance_path, "dossierforge.db")
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-key-change-in-prod"),
        SQLALCHEMY_DATABASE_URI=_normalize_db_uri(
            os.environ.get("DATABASE_URL", default_db)
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        DOSSIER_DATA_DIR=os.environ.get(
            "DOSSIER_DATA_DIR", os.path.join(app.instance_path, "dossier_data")
        ),
        # When True, scan jobs run inline (synchronously) instead of on the
        # background worker. Useful for tests and simple single-process setups.
        SCAN_JOBS_EAGER=os.environ.get("SCAN_JOBS_EAGER", "").lower()
        in ("1", "true", "yes"),
    )
    if config:
        app.config.update(config)

    os.makedirs(app.config["DOSSIER_DATA_DIR"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "error"

    with app.app_context():
        db.create_all()

    register_routes(app)
    return app


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def _dossier_data_dir(dossier_id):
    from flask import current_app

    path = os.path.join(current_app.config["DOSSIER_DATA_DIR"], str(dossier_id))
    os.makedirs(path, exist_ok=True)
    return path


def _empty_lists():
    return {"ip_addresses": [], "domains": [], "emails": [], "social_media": []}


def _load_lists(target_dir):
    """Aggregated lists (domains/emails/ips/social) live in overview.json."""
    path = os.path.join(target_dir, "overview.json")
    if not os.path.exists(path):
        return _empty_lists()
    with open(path) as f:
        return json.load(f)


def _save_lists(target_dir, data):
    with open(os.path.join(target_dir, "overview.json"), "w") as f:
        json.dump(data, f, indent=2)


def _get_dossier_access(dossier_id, need="view"):
    """Return (dossier, role) enforcing access.

    role is "owner", "editor", or "viewer". `need` is one of:
      - "view":  owner or any collaborator
      - "edit":  owner or editor collaborator
      - "owner": owner only
    404 hides existence from users with no access; 403 signals insufficient role.
    """
    dossier = db.session.get(Dossier, dossier_id)
    if dossier is None:
        abort(404)
    if dossier.owner_id == current_user.id:
        return dossier, "owner"
    if need == "owner":
        abort(404)
    share = (
        db.session.query(DossierShare)
        .filter_by(dossier_id=dossier_id, user_id=current_user.id)
        .first()
    )
    if share is None:
        abort(404)
    if need == "edit" and share.role != DossierShare.ROLE_EDITOR:
        abort(403)
    return dossier, share.role


def _build_report(dossier, target_dir):
    lists = _load_lists(target_dir)
    return {
        "name": dossier.name,
        "alias": dossier.alias,
        "organization": dossier.organization,
        "authorization_scope": dossier.authorization_scope,
        "attested_at": dossier.attested_at.isoformat(),
        "created_at": dossier.created_at.isoformat(),
        "tags": [t.name for t in dossier.tags],
        "notes": [
            {
                "author": n.author.email,
                "body": n.body,
                "at": n.created_at.isoformat(),
            }
            for n in dossier.notes
        ],
        "assets": lists,
        "whois": get_whois_summary(target_dir),
        "nmap": get_nmap_summary(target_dir),
        "open_ports": get_open_ports(target_dir),
        "osint": get_osint_summary(target_dir),
        "audit": [
            {
                "action": a.action,
                "detail": a.detail,
                "at": a.created_at.isoformat(),
            }
            for a in dossier.audit_logs
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _slugify(value):
    slug = "".join(c if c.isalnum() else "-" for c in value.lower()).strip("-")
    return slug or "dossier"


def _audit(action, dossier_id=None, detail=""):
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            dossier_id=dossier_id,
            action=action,
            detail=detail[:512],
        )
    )
    db.session.commit()


def _dispatch_scan(job, target_dir):
    """Run the recon module for a job and return a human-readable message.

    Raises on failure so the caller can mark the job as errored.
    """
    module = job.module
    params = job.params or ""
    if module == "whois":
        result = run_whois(params, target_dir)
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(result["error"])
        lists = _load_lists(target_dir)
        if params not in lists["domains"]:
            lists["domains"].append(params)
            _save_lists(target_dir, lists)
        return f"WHOIS completed for {params}"
    if module == "nmap":
        scan_type, _, target = params.partition("|")
        scan_type = scan_type or "basic"
        result = run_nmap_scan(target, target_dir, scan_type)
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(result["error"])
        lists = _load_lists(target_dir)
        if target.replace(".", "").replace(":", "").isdigit() or ":" in target:
            if target not in lists["ip_addresses"]:
                lists["ip_addresses"].append(target)
        elif target not in lists["domains"]:
            lists["domains"].append(target)
        _save_lists(target_dir, lists)
        return f"Nmap {scan_type} scan completed for {target}"
    if module == "social":
        search_social_media(params, target_dir)
        return f"Social media search completed for {params}"
    if module == "emails":
        result = search_emails(params, target_dir)
        lists = _load_lists(target_dir)
        for email in result.get("emails", []):
            if email not in lists["emails"]:
                lists["emails"].append(email)
        _save_lists(target_dir, lists)
        return f"Email search completed for {params}"
    if module == "breach":
        check_breach_data(params, target_dir)
        return f"Breach check completed for {params}"
    if module == "github":
        search_github_info(params, target_dir)
        return f"GitHub search completed for {params}"
    raise RuntimeError(f"Unknown module: {module}")


def _execute_scan_job(app, job_id):
    """Worker entrypoint: runs in a background thread with its own app context."""
    with app.app_context():
        job = db.session.get(ScanJob, job_id)
        if job is None:
            return
        job.status = ScanJob.STATUS_RUNNING
        job.started_at = datetime.now(timezone.utc)
        db.session.commit()
        target_dir = os.path.join(app.config["DOSSIER_DATA_DIR"], str(job.dossier_id))
        os.makedirs(target_dir, exist_ok=True)
        try:
            job.message = _dispatch_scan(job, target_dir)
            job.status = ScanJob.STATUS_SUCCESS
        except Exception as exc:  # noqa: BLE001 - record any failure on the job
            job.status = ScanJob.STATUS_ERROR
            job.message = str(exc)[:1024]
        job.finished_at = datetime.now(timezone.utc)
        db.session.add(
            AuditLog(
                user_id=job.user_id,
                dossier_id=job.dossier_id,
                action=f"run_{job.module}",
                detail=(job.params or "")[:512],
            )
        )
        db.session.commit()


def _enqueue_scan(dossier, module, params):
    job = ScanJob(
        dossier_id=dossier.id,
        user_id=current_user.id,
        module=module,
        params=params,
        status=ScanJob.STATUS_QUEUED,
    )
    db.session.add(job)
    db.session.commit()
    app = current_app._get_current_object()
    if app.config.get("SCAN_JOBS_EAGER"):
        _execute_scan_job(app, job.id)
    else:
        _scan_executor.submit(_execute_scan_job, app, job.id)
    return job


def register_routes(app):
    # ---------------------------------------------------------------- auth
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            if not email or not password:
                flash("Email and password are required", "error")
                return render_template("register.html")
            if len(password) < 8:
                flash("Password must be at least 8 characters", "error")
                return render_template("register.html")
            if db.session.query(User).filter_by(email=email).first():
                flash("An account with that email already exists", "error")
                return render_template("register.html")
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            _audit("register", detail=email)
            flash("Account created. Welcome to DossierForge.", "success")
            return redirect(url_for("index"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            user = db.session.query(User).filter_by(email=email).first()
            if user is None or not user.check_password(password):
                flash("Invalid email or password", "error")
                return render_template("login.html")
            login_user(user)
            _audit("login", detail=email)
            return redirect(url_for("index"))
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        flash("Signed out", "success")
        return redirect(url_for("login"))

    # ----------------------------------------------------------- dossiers
    @app.route("/")
    @login_required
    def index():
        query = (request.args.get("q") or "").strip()

        def matches(dossier):
            if not query:
                return True
            q = query.lower()
            haystack = [dossier.name or "", dossier.organization or ""]
            haystack += [t.name for t in dossier.tags]
            return any(q in value.lower() for value in haystack)

        dossiers = [
            d
            for d in db.session.query(Dossier)
            .filter_by(owner_id=current_user.id)
            .order_by(Dossier.created_at.desc())
            .all()
            if matches(d)
        ]
        shared = [
            (d, role)
            for d, role in db.session.query(Dossier, DossierShare.role)
            .join(DossierShare, DossierShare.dossier_id == Dossier.id)
            .filter(DossierShare.user_id == current_user.id)
            .order_by(Dossier.created_at.desc())
            .all()
            if matches(d)
        ]
        return render_template(
            "index.html", dossiers=dossiers, shared=shared, query=query
        )

    @app.route("/dossier/new", methods=["GET", "POST"])
    @login_required
    def new_dossier():
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            if not name:
                flash("Name is required", "error")
                return render_template("new_dossier.html")
            if not request.form.get("authorized"):
                flash(
                    "You must confirm you are authorized to investigate this "
                    "target before creating a dossier.",
                    "error",
                )
                return render_template("new_dossier.html")
            dossier = Dossier(
                owner_id=current_user.id,
                name=name,
                alias=(request.form.get("alias") or "").strip(),
                organization=(request.form.get("organization") or "").strip(),
                authorization_scope=(
                    request.form.get("authorization_scope") or ""
                ).strip(),
            )
            db.session.add(dossier)
            db.session.commit()
            _save_lists(_dossier_data_dir(dossier.id), _empty_lists())
            _audit("create_dossier", dossier_id=dossier.id, detail=name)
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        return render_template("new_dossier.html")

    @app.route("/dossier/<int:dossier_id>")
    @login_required
    def dossier_overview(dossier_id):
        dossier, role = _get_dossier_access(dossier_id, "view")
        target_dir = _dossier_data_dir(dossier.id)
        lists = _load_lists(target_dir)
        overview = {
            "name": dossier.name,
            "alias": dossier.alias,
            "organization": dossier.organization,
            "ip_addresses": lists.get("ip_addresses", []),
            "domains": lists.get("domains", []),
            "emails": lists.get("emails", []),
            "social_media": lists.get("social_media", []),
        }
        return render_template(
            "dossier_overview.html",
            dossier=dossier,
            overview=overview,
            role=role,
            can_edit=role in ("owner", "editor"),
            collaborators=dossier.shares if role == "owner" else None,
            notes=dossier.notes,
            tags=dossier.tags,
            scan_jobs=dossier.scan_jobs,
            pending_jobs=any(j.is_pending for j in dossier.scan_jobs),
            whois_summary=get_whois_summary(target_dir),
            nmap_summary=get_nmap_summary(target_dir),
            open_ports=get_open_ports(target_dir),
            osint_summary=get_osint_summary(target_dir),
            audit_logs=dossier.audit_logs,
        )

    @app.route("/dossier/<int:dossier_id>/export.<fmt>")
    @login_required
    def export_dossier(dossier_id, fmt):
        dossier, _role = _get_dossier_access(dossier_id, "view")
        target_dir = _dossier_data_dir(dossier.id)
        report = _build_report(dossier, target_dir)
        slug = f"{_slugify(dossier.name)}-{dossier.id}"
        if fmt == "json":
            body, mimetype, ext = render_json(report), "application/json", "json"
        elif fmt in ("md", "markdown"):
            body, mimetype, ext = render_markdown(report), "text/markdown", "md"
        else:
            abort(404)
        _audit("export_dossier", dossier_id=dossier.id, detail=ext)
        return Response(
            body,
            mimetype=mimetype,
            headers={"Content-Disposition": f'attachment; filename="{slug}.{ext}"'},
        )

    @app.route("/dossier/<int:dossier_id>/delete", methods=["POST"])
    @login_required
    def delete_dossier(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "owner")
        name = dossier.name
        target_dir = os.path.join(app.config["DOSSIER_DATA_DIR"], str(dossier.id))
        db.session.delete(dossier)
        db.session.commit()
        shutil.rmtree(target_dir, ignore_errors=True)
        # Dossier (and its audit rows) are gone; record a user-level entry.
        _audit("delete_dossier", dossier_id=None, detail=name)
        flash(f"Deleted dossier '{name}'", "success")
        return redirect(url_for("index"))

    # -------------------------------------------------------- collaboration
    @app.route("/dossier/<int:dossier_id>/share", methods=["POST"])
    @login_required
    def share_dossier(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "owner")
        email = (request.form.get("email") or "").strip().lower()
        role = request.form.get("role", DossierShare.ROLE_VIEWER)
        if role not in (DossierShare.ROLE_VIEWER, DossierShare.ROLE_EDITOR):
            role = DossierShare.ROLE_VIEWER
        if not email:
            flash("Collaborator email is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        collaborator = db.session.query(User).filter_by(email=email).first()
        if collaborator is None:
            flash(f"No account found for {email}", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        if collaborator.id == dossier.owner_id:
            flash("You already own this dossier", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        share = (
            db.session.query(DossierShare)
            .filter_by(dossier_id=dossier.id, user_id=collaborator.id)
            .first()
        )
        if share:
            share.role = role
            flash(f"Updated {email} to {role}", "success")
        else:
            db.session.add(
                DossierShare(dossier_id=dossier.id, user_id=collaborator.id, role=role)
            )
            flash(f"Shared with {email} as {role}", "success")
        db.session.commit()
        _audit("share_dossier", dossier_id=dossier.id, detail=f"{email}:{role}")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/unshare", methods=["POST"])
    @login_required
    def unshare_dossier(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "owner")
        share_id = request.form.get("share_id")
        share = db.session.get(DossierShare, int(share_id)) if share_id else None
        if share is None or share.dossier_id != dossier.id:
            abort(404)
        email = share.user.email
        db.session.delete(share)
        db.session.commit()
        _audit("unshare_dossier", dossier_id=dossier.id, detail=email)
        flash(f"Removed {email}", "success")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    # --------------------------------------------------------- notes & tags
    @app.route("/dossier/<int:dossier_id>/notes", methods=["POST"])
    @login_required
    def add_note(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        body = (request.form.get("body") or "").strip()
        if not body:
            flash("Note cannot be empty", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        db.session.add(
            Note(dossier_id=dossier.id, author_id=current_user.id, body=body)
        )
        db.session.commit()
        _audit("add_note", dossier_id=dossier.id, detail=body[:80])
        flash("Note added", "success")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/notes/<int:note_id>/delete", methods=["POST"])
    @login_required
    def delete_note(dossier_id, note_id):
        dossier, role = _get_dossier_access(dossier_id, "edit")
        note = db.session.get(Note, note_id)
        if note is None or note.dossier_id != dossier.id:
            abort(404)
        # Owners can remove any note; editors can remove only their own.
        if role != "owner" and note.author_id != current_user.id:
            abort(403)
        db.session.delete(note)
        db.session.commit()
        _audit("delete_note", dossier_id=dossier.id)
        flash("Note deleted", "success")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/tags", methods=["POST"])
    @login_required
    def add_tag(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        name = (request.form.get("name") or "").strip().lower()
        if not name:
            flash("Tag cannot be empty", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        name = name[:64]
        exists = (
            db.session.query(Tag).filter_by(dossier_id=dossier.id, name=name).first()
        )
        if exists:
            flash(f"Tag '{name}' already exists", "error")
        else:
            db.session.add(Tag(dossier_id=dossier.id, name=name))
            db.session.commit()
            _audit("add_tag", dossier_id=dossier.id, detail=name)
            flash(f"Added tag '{name}'", "success")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/tags/<int:tag_id>/delete", methods=["POST"])
    @login_required
    def delete_tag(dossier_id, tag_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        tag = db.session.get(Tag, tag_id)
        if tag is None or tag.dossier_id != dossier.id:
            abort(404)
        name = tag.name
        db.session.delete(tag)
        db.session.commit()
        _audit("remove_tag", dossier_id=dossier.id, detail=name)
        flash(f"Removed tag '{name}'", "success")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    # ----------------------------------------------- recon modules (async)
    def _queue_and_redirect(dossier, module, params, label):
        _enqueue_scan(dossier, module, params)
        flash(f"Queued {label}", "success")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/whois", methods=["POST"])
    @login_required
    def run_whois_query(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        domain = request.form.get("domain")
        if not domain:
            flash("Domain is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        return _queue_and_redirect(dossier, "whois", domain, f"WHOIS for {domain}")

    @app.route("/dossier/<int:dossier_id>/nmap", methods=["POST"])
    @login_required
    def run_nmap_scan_route(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        target = request.form.get("target")
        scan_type = request.form.get("scan_type", "basic")
        if not target:
            flash("Target is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        return _queue_and_redirect(
            dossier,
            "nmap",
            f"{scan_type}|{target}",
            f"nmap {scan_type} scan for {target}",
        )

    @app.route("/dossier/<int:dossier_id>/osint/social", methods=["POST"])
    @login_required
    def run_social_media_search(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        target = request.form.get("target")
        if not target:
            flash("Target is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        return _queue_and_redirect(
            dossier, "social", target, f"social media search for {target}"
        )

    @app.route("/dossier/<int:dossier_id>/osint/emails", methods=["POST"])
    @login_required
    def run_email_search(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        domain = request.form.get("domain")
        if not domain:
            flash("Domain is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        return _queue_and_redirect(
            dossier, "emails", domain, f"email search for {domain}"
        )

    @app.route("/dossier/<int:dossier_id>/osint/breach", methods=["POST"])
    @login_required
    def run_breach_check(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        email = request.form.get("email")
        if not email:
            flash("Email is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        return _queue_and_redirect(
            dossier, "breach", email, f"breach check for {email}"
        )

    @app.route("/dossier/<int:dossier_id>/osint/github", methods=["POST"])
    @login_required
    def run_github_search(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "edit")
        username = request.form.get("username")
        if not username:
            flash("Username is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        return _queue_and_redirect(
            dossier, "github", username, f"GitHub search for {username}"
        )


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, port=5001)
