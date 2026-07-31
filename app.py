"""DossierForge — multi-user OSINT dossier SaaS.

Authorized use only. Every dossier requires the user to attest that they are
authorized to investigate the target, and every recon action is written to an
audit trail. Dossiers are isolated per user account.
"""

import json
import os
import secrets
import shutil
import sys
import threading
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
from flask_migrate import Migrate, upgrade as migrate_upgrade

from models import (
    AuditLog,
    Dossier,
    DossierOrgAccess,
    DossierShare,
    Invitation,
    Note,
    Organization,
    OrgMembership,
    ScanJob,
    Tag,
    User,
    db,
)
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
migrate = Migrate()
# Durable DB-backed scan worker: jobs live as ScanJob rows; a daemon thread
# polls and claims them. Survives process restarts (orphaned "running" rows are
# reclaimed to "queued" on startup). One worker thread per process.
_scan_worker_lock = threading.Lock()
_scan_worker_started = False
_scan_worker_stop = threading.Event()


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
        # Durable poller (ignored when SCAN_JOBS_EAGER / TESTING).
        SCAN_WORKER_ENABLED=os.environ.get("SCAN_WORKER_ENABLED", "true").lower()
        in ("1", "true", "yes"),
        SCAN_WORKER_POLL_SECONDS=float(
            os.environ.get("SCAN_WORKER_POLL_SECONDS", "0.5")
        ),
        # Skip auto-applying migrations (e.g. while generating a new revision).
        SKIP_DB_UPGRADE=os.environ.get("SKIP_DB_UPGRADE", "").lower()
        in ("1", "true", "yes"),
    )
    if config:
        app.config.update(config)

    os.makedirs(app.config["DOSSIER_DATA_DIR"], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "error"

    with app.app_context():
        # Tests use a throwaway SQLite DB and create_all for speed. Everywhere
        # else we apply Alembic migrations so schema changes don't need a wipe.
        if app.config.get("TESTING"):
            db.create_all()
        elif not app.config.get("SKIP_DB_UPGRADE"):
            migrations_dir = os.path.join(os.path.dirname(__file__), "migrations")
            if os.path.isdir(migrations_dir):
                migrate_upgrade()
            else:
                db.create_all()

    register_routes(app)
    _maybe_start_scan_worker(app)
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


def _user_org_ids(user_id):
    return [
        m.org_id
        for m in db.session.query(OrgMembership).filter_by(user_id=user_id).all()
    ]


def _my_memberships():
    return db.session.query(OrgMembership).filter_by(user_id=current_user.id).all()


def _effective_shared_role(dossier, user_id):
    """Best role a non-owner user has on a dossier via direct or org shares.

    Returns "editor", "viewer", or None. Editor beats viewer when both apply.
    """
    roles = set()
    share = (
        db.session.query(DossierShare)
        .filter_by(dossier_id=dossier.id, user_id=user_id)
        .first()
    )
    if share is not None:
        roles.add(share.role)
    org_ids = _user_org_ids(user_id)
    if org_ids:
        for access in (
            db.session.query(DossierOrgAccess)
            .filter(
                DossierOrgAccess.dossier_id == dossier.id,
                DossierOrgAccess.org_id.in_(org_ids),
            )
            .all()
        ):
            roles.add(access.role)
    if not roles:
        return None
    return "editor" if DossierShare.ROLE_EDITOR in roles else "viewer"


def _get_org_membership(org_id, need_admin=False):
    """Return (org, membership) enforcing that current_user belongs to the org."""
    org = db.session.get(Organization, org_id)
    if org is None:
        abort(404)
    membership = (
        db.session.query(OrgMembership)
        .filter_by(org_id=org_id, user_id=current_user.id)
        .first()
    )
    if membership is None:
        abort(404)
    if need_admin and membership.role != OrgMembership.ROLE_ADMIN:
        abort(403)
    return org, membership


def _get_dossier_access(dossier_id, need="view"):
    """Return (dossier, role) enforcing access.

    role is "owner", "editor", or "viewer". Access can come from ownership, a
    direct share, or membership in an organization the dossier is shared with.
    `need` is one of:
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
    role = _effective_shared_role(dossier, current_user.id)
    if role is None:
        abort(404)
    if need == "edit" and role != DossierShare.ROLE_EDITOR:
        abort(403)
    return dossier, role


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


def _new_invite_token():
    return secrets.token_urlsafe(32)


def _apply_invitation(invite, user):
    """Apply a pending invitation to a user. Returns a short status message."""
    if invite.status != Invitation.STATUS_PENDING:
        return None
    if invite.kind == Invitation.KIND_ORG and invite.org_id:
        existing = (
            db.session.query(OrgMembership)
            .filter_by(org_id=invite.org_id, user_id=user.id)
            .first()
        )
        if existing:
            existing.role = invite.role
        else:
            db.session.add(
                OrgMembership(org_id=invite.org_id, user_id=user.id, role=invite.role)
            )
        label = invite.organization.name if invite.organization else "organization"
        return f"Joined {label} as {invite.role}"
    if invite.kind == Invitation.KIND_DOSSIER and invite.dossier_id:
        if invite.dossier and invite.dossier.owner_id == user.id:
            invite.status = Invitation.STATUS_REVOKED
            return None
        existing = (
            db.session.query(DossierShare)
            .filter_by(dossier_id=invite.dossier_id, user_id=user.id)
            .first()
        )
        if existing:
            existing.role = invite.role
        else:
            db.session.add(
                DossierShare(
                    dossier_id=invite.dossier_id, user_id=user.id, role=invite.role
                )
            )
        label = invite.dossier.name if invite.dossier else "dossier"
        return f"Gained {invite.role} access to {label}"
    return None


def _finalize_invitation(invite, user):
    msg = _apply_invitation(invite, user)
    if msg:
        invite.status = Invitation.STATUS_ACCEPTED
        invite.accepted_at = datetime.now(timezone.utc)
    return msg


def _claim_pending_invites(user):
    """Accept all pending invitations for the user's email. Returns count claimed."""
    pending = (
        db.session.query(Invitation)
        .filter_by(email=user.email, status=Invitation.STATUS_PENDING)
        .all()
    )
    claimed = 0
    for invite in pending:
        if _finalize_invitation(invite, user):
            claimed += 1
    if pending:
        db.session.commit()
    return claimed


def _create_or_apply_invite(
    *, kind, email, role, invited_by_id, org_id=None, dossier_id=None
):
    """Create a pending invite; if the invitee already has an account, apply it.

    Returns (invite, applied_immediately: bool).
    """
    invite = Invitation(
        token=_new_invite_token(),
        email=email,
        kind=kind,
        role=role,
        org_id=org_id,
        dossier_id=dossier_id,
        invited_by_id=invited_by_id,
        status=Invitation.STATUS_PENDING,
    )
    db.session.add(invite)
    db.session.flush()
    user = db.session.query(User).filter_by(email=email).first()
    if user is not None:
        applied = bool(_finalize_invitation(invite, user))
        db.session.commit()
        return invite, applied
    db.session.commit()
    return invite, False


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
    """Worker entrypoint: runs with an app context (thread or eager call)."""
    with app.app_context():
        job = db.session.get(ScanJob, job_id)
        if job is None:
            return
        # Idempotent: claim may have already set running; eager path needs it.
        if job.status != ScanJob.STATUS_RUNNING:
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


def reclaim_orphaned_scan_jobs():
    """Reset jobs left 'running' after a crash/restart so they can be retried."""
    orphaned = db.session.query(ScanJob).filter_by(status=ScanJob.STATUS_RUNNING).all()
    for job in orphaned:
        job.status = ScanJob.STATUS_QUEUED
        job.started_at = None
        job.message = "Requeued after worker restart"
    if orphaned:
        db.session.commit()
    return len(orphaned)


def claim_next_scan_job():
    """Atomically claim the oldest queued job. Returns job id or None."""
    job = (
        db.session.query(ScanJob)
        .filter_by(status=ScanJob.STATUS_QUEUED)
        .order_by(ScanJob.created_at.asc())
        .first()
    )
    if job is None:
        return None
    # Conditional update so two workers cannot claim the same row.
    rows = (
        db.session.query(ScanJob)
        .filter(
            ScanJob.id == job.id,
            ScanJob.status == ScanJob.STATUS_QUEUED,
        )
        .update(
            {
                "status": ScanJob.STATUS_RUNNING,
                "started_at": datetime.now(timezone.utc),
            },
            synchronize_session=False,
        )
    )
    db.session.commit()
    if rows == 0:
        return None
    return job.id


def process_one_queued_scan(app):
    """Claim and run at most one queued job. Returns job id or None."""
    with app.app_context():
        job_id = claim_next_scan_job()
    if job_id is None:
        return None
    _execute_scan_job(app, job_id)
    return job_id


def _scan_worker_loop(app):
    poll = float(app.config.get("SCAN_WORKER_POLL_SECONDS", 0.5))
    with app.app_context():
        reclaim_orphaned_scan_jobs()
    while not _scan_worker_stop.is_set():
        job_id = process_one_queued_scan(app)
        if job_id is None:
            _scan_worker_stop.wait(timeout=poll)


def _maybe_start_scan_worker(app):
    """Start the durable poller once per process (skipped for tests / eager)."""
    global _scan_worker_started
    if app.config.get("TESTING") or app.config.get("SCAN_JOBS_EAGER"):
        return
    if not app.config.get("SCAN_WORKER_ENABLED", True):
        return
    # Avoid starting a poller against the real instance DB when pytest imports
    # this module (module-level ``app = create_app()``).
    if "pytest" in sys.modules:
        return
    # Flask debug reloader parent: skip (child has WERKZEUG_RUN_MAIN=true).
    # Plain gunicorn / non-reloader imports leave the var unset — still start.
    if (
        os.environ.get("WERKZEUG_SERVER_FD")
        and os.environ.get("WERKZEUG_RUN_MAIN") != "true"
    ):
        return
    with _scan_worker_lock:
        if _scan_worker_started:
            return
        _scan_worker_started = True
        _scan_worker_stop.clear()
        thread = threading.Thread(
            target=_scan_worker_loop,
            args=(app,),
            name="scan-worker",
            daemon=True,
        )
        thread.start()


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
        # Tests / single-process: run inline for determinism.
        _execute_scan_job(app, job.id)
    # Otherwise the durable DB poller claims the queued row.
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
            claimed = _claim_pending_invites(user)
            _audit("register", detail=email)
            if claimed:
                flash(
                    f"Account created. Accepted {claimed} pending invitation(s).",
                    "success",
                )
            else:
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
            claimed = _claim_pending_invites(user)
            _audit("login", detail=email)
            if claimed:
                flash(f"Accepted {claimed} pending invitation(s).", "success")
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
        # Combine direct shares and organization shares, deduped by dossier
        # (editor beats viewer when a dossier is reachable both ways).
        shared_map = {}
        for d, role in (
            db.session.query(Dossier, DossierShare.role)
            .join(DossierShare, DossierShare.dossier_id == Dossier.id)
            .filter(DossierShare.user_id == current_user.id)
            .all()
        ):
            shared_map[d.id] = [d, role]
        org_ids = _user_org_ids(current_user.id)
        if org_ids:
            for d, role in (
                db.session.query(Dossier, DossierOrgAccess.role)
                .join(DossierOrgAccess, DossierOrgAccess.dossier_id == Dossier.id)
                .filter(DossierOrgAccess.org_id.in_(org_ids))
                .all()
            ):
                if d.owner_id == current_user.id:
                    continue
                if d.id in shared_map:
                    if role == DossierShare.ROLE_EDITOR:
                        shared_map[d.id][1] = DossierShare.ROLE_EDITOR
                else:
                    shared_map[d.id] = [d, role]
        shared = sorted(
            ((d, role) for d, role in shared_map.values() if matches(d)),
            key=lambda pair: pair[0].created_at,
            reverse=True,
        )
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

    @app.route("/dossier/<int:dossier_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_dossier(dossier_id):
        # Metadata (incl. authorization scope) is owner-only; collaborators
        # use notes/tags for their contributions.
        dossier, _role = _get_dossier_access(dossier_id, "owner")
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            if not name:
                flash("Name is required", "error")
                return render_template("edit_dossier.html", dossier=dossier)
            dossier.name = name
            dossier.alias = (request.form.get("alias") or "").strip()
            dossier.organization = (request.form.get("organization") or "").strip()
            dossier.authorization_scope = (
                request.form.get("authorization_scope") or ""
            ).strip()
            db.session.commit()
            _audit("edit_dossier", dossier_id=dossier.id, detail=name)
            flash("Dossier updated", "success")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        return render_template("edit_dossier.html", dossier=dossier)

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
            pending_invites=(
                db.session.query(Invitation)
                .filter_by(
                    dossier_id=dossier.id,
                    kind=Invitation.KIND_DOSSIER,
                    status=Invitation.STATUS_PENDING,
                )
                .order_by(Invitation.created_at.desc())
                .all()
                if role == "owner"
                else None
            ),
            my_orgs=(
                [m.organization for m in _my_memberships()] if role == "owner" else None
            ),
            org_shares=dossier.org_access if role == "owner" else None,
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
        if email == current_user.email:
            flash("You already own this dossier", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        invite, applied = _create_or_apply_invite(
            kind=Invitation.KIND_DOSSIER,
            email=email,
            role=role,
            invited_by_id=current_user.id,
            dossier_id=dossier.id,
        )
        _audit("share_dossier", dossier_id=dossier.id, detail=f"{email}:{role}")
        if applied:
            flash(f"Shared with {email} as {role}", "success")
        else:
            flash(
                f"Invitation sent to {email} as {role}. "
                f"They can accept via /invite/{invite.token} after signing up.",
                "success",
            )
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

    # ------------------------------------------------------ organizations
    @app.route("/orgs")
    @login_required
    def orgs():
        memberships = (
            db.session.query(OrgMembership).filter_by(user_id=current_user.id).all()
        )
        return render_template("orgs.html", memberships=memberships)

    @app.route("/orgs", methods=["POST"])
    @login_required
    def create_org():
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Organization name is required", "error")
            return redirect(url_for("orgs"))
        org = Organization(name=name)
        db.session.add(org)
        db.session.flush()
        db.session.add(
            OrgMembership(
                org_id=org.id,
                user_id=current_user.id,
                role=OrgMembership.ROLE_ADMIN,
            )
        )
        db.session.commit()
        _audit("create_org", detail=name)
        flash(f"Created organization '{name}'", "success")
        return redirect(url_for("org_detail", org_id=org.id))

    @app.route("/orgs/<int:org_id>")
    @login_required
    def org_detail(org_id):
        org, membership = _get_org_membership(org_id)
        shared_dossiers = (
            db.session.query(Dossier, DossierOrgAccess.role)
            .join(DossierOrgAccess, DossierOrgAccess.dossier_id == Dossier.id)
            .filter(DossierOrgAccess.org_id == org.id)
            .all()
        )
        pending_invites = (
            db.session.query(Invitation)
            .filter_by(
                org_id=org.id,
                kind=Invitation.KIND_ORG,
                status=Invitation.STATUS_PENDING,
            )
            .order_by(Invitation.created_at.desc())
            .all()
        )
        return render_template(
            "org_detail.html",
            org=org,
            membership=membership,
            is_admin=membership.role == OrgMembership.ROLE_ADMIN,
            shared_dossiers=shared_dossiers,
            pending_invites=pending_invites,
        )

    @app.route("/orgs/<int:org_id>/members", methods=["POST"])
    @login_required
    def add_org_member(org_id):
        org, _membership = _get_org_membership(org_id, need_admin=True)
        email = (request.form.get("email") or "").strip().lower()
        role = request.form.get("role", OrgMembership.ROLE_MEMBER)
        if role not in (OrgMembership.ROLE_ADMIN, OrgMembership.ROLE_MEMBER):
            role = OrgMembership.ROLE_MEMBER
        if not email:
            flash("Member email is required", "error")
            return redirect(url_for("org_detail", org_id=org.id))
        if email == current_user.email:
            flash("You are already a member", "error")
            return redirect(url_for("org_detail", org_id=org.id))
        invite, applied = _create_or_apply_invite(
            kind=Invitation.KIND_ORG,
            email=email,
            role=role,
            invited_by_id=current_user.id,
            org_id=org.id,
        )
        _audit("add_org_member", detail=f"{org.name}:{email}:{role}")
        if applied:
            flash(f"Added {email} as {role}", "success")
        else:
            flash(
                f"Invitation sent to {email} as {role}. "
                f"They can accept via /invite/{invite.token} after signing up.",
                "success",
            )
        return redirect(url_for("org_detail", org_id=org.id))

    @app.route("/invites/<int:invite_id>/revoke", methods=["POST"])
    @login_required
    def revoke_invite(invite_id):
        invite = db.session.get(Invitation, invite_id)
        if invite is None or invite.status != Invitation.STATUS_PENDING:
            abort(404)
        if invite.kind == Invitation.KIND_ORG:
            _get_org_membership(invite.org_id, need_admin=True)
            redirect_to = url_for("org_detail", org_id=invite.org_id)
        elif invite.kind == Invitation.KIND_DOSSIER:
            _get_dossier_access(invite.dossier_id, "owner")
            redirect_to = url_for("dossier_overview", dossier_id=invite.dossier_id)
        else:
            abort(404)
        invite.status = Invitation.STATUS_REVOKED
        db.session.commit()
        _audit("revoke_invite", detail=f"{invite.email}:{invite.kind}")
        flash(f"Revoked invitation for {invite.email}", "success")
        return redirect(redirect_to)

    @app.route("/invite/<token>", methods=["GET", "POST"])
    def accept_invite(token):
        invite = db.session.query(Invitation).filter_by(token=token).first()
        if invite is None:
            abort(404)
        if invite.status != Invitation.STATUS_PENDING:
            flash("This invitation is no longer pending.", "error")
            return redirect(
                url_for("index") if current_user.is_authenticated else url_for("login")
            )
        if request.method == "GET" and not current_user.is_authenticated:
            return render_template("accept_invite.html", invite=invite)
        if not current_user.is_authenticated:
            flash("Sign in or create an account to accept this invitation.", "error")
            return redirect(url_for("register"))
        if current_user.email != invite.email:
            flash(
                f"This invitation was sent to {invite.email}. "
                "Sign in with that email to accept it.",
                "error",
            )
            return redirect(url_for("index"))
        msg = _finalize_invitation(invite, current_user)
        db.session.commit()
        if msg:
            _audit("accept_invite", detail=f"{invite.kind}:{invite.email}")
            flash(msg, "success")
        else:
            flash("Could not accept this invitation.", "error")
        return redirect(url_for("index"))

    @app.route("/orgs/<int:org_id>/members/<int:user_id>/remove", methods=["POST"])
    @login_required
    def remove_org_member(org_id, user_id):
        org, _membership = _get_org_membership(org_id, need_admin=True)
        target = (
            db.session.query(OrgMembership)
            .filter_by(org_id=org.id, user_id=user_id)
            .first()
        )
        if target is None:
            abort(404)
        admin_count = (
            db.session.query(OrgMembership)
            .filter_by(org_id=org.id, role=OrgMembership.ROLE_ADMIN)
            .count()
        )
        if target.role == OrgMembership.ROLE_ADMIN and admin_count <= 1:
            flash("Cannot remove the last admin", "error")
            return redirect(url_for("org_detail", org_id=org.id))
        email = target.user.email
        db.session.delete(target)
        db.session.commit()
        _audit("remove_org_member", detail=f"{org.name}:{email}")
        flash(f"Removed {email} from {org.name}", "success")
        return redirect(url_for("org_detail", org_id=org.id))

    @app.route("/dossier/<int:dossier_id>/org-share", methods=["POST"])
    @login_required
    def org_share_dossier(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "owner")
        org_id = request.form.get("org_id")
        role = request.form.get("role", "viewer")
        if role not in (DossierShare.ROLE_VIEWER, DossierShare.ROLE_EDITOR):
            role = DossierShare.ROLE_VIEWER
        org, _membership = _get_org_membership(int(org_id)) if org_id else (None, None)
        if org is None:
            flash("Select one of your organizations", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        access = (
            db.session.query(DossierOrgAccess)
            .filter_by(dossier_id=dossier.id, org_id=org.id)
            .first()
        )
        if access:
            access.role = role
            flash(f"Updated {org.name} to {role}", "success")
        else:
            db.session.add(
                DossierOrgAccess(dossier_id=dossier.id, org_id=org.id, role=role)
            )
            flash(f"Shared with {org.name} as {role}", "success")
        db.session.commit()
        _audit("org_share_dossier", dossier_id=dossier.id, detail=f"{org.name}:{role}")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/org-unshare", methods=["POST"])
    @login_required
    def org_unshare_dossier(dossier_id):
        dossier, _role = _get_dossier_access(dossier_id, "owner")
        access_id = request.form.get("access_id")
        access = db.session.get(DossierOrgAccess, int(access_id)) if access_id else None
        if access is None or access.dossier_id != dossier.id:
            abort(404)
        org_name = access.organization.name
        db.session.delete(access)
        db.session.commit()
        _audit("org_unshare_dossier", dossier_id=dossier.id, detail=org_name)
        flash(f"Removed {org_name}", "success")
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
