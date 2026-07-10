"""DossierForge — multi-user OSINT dossier SaaS.

Authorized use only. Every dossier requires the user to attest that they are
authorized to investigate the target, and every recon action is written to an
audit trail. Dossiers are isolated per user account.
"""

import json
import os
import shutil
from datetime import datetime, timezone

from flask import (
    Flask,
    Response,
    abort,
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

from models import AuditLog, Dossier, User, db
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


def _get_owned_dossier(dossier_id):
    dossier = db.session.get(Dossier, dossier_id)
    if dossier is None or dossier.owner_id != current_user.id:
        abort(404)
    return dossier


def _build_report(dossier, target_dir):
    lists = _load_lists(target_dir)
    return {
        "name": dossier.name,
        "alias": dossier.alias,
        "organization": dossier.organization,
        "authorization_scope": dossier.authorization_scope,
        "attested_at": dossier.attested_at.isoformat(),
        "created_at": dossier.created_at.isoformat(),
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
        dossiers = (
            db.session.query(Dossier)
            .filter_by(owner_id=current_user.id)
            .order_by(Dossier.created_at.desc())
            .all()
        )
        return render_template("index.html", dossiers=dossiers)

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
        dossier = _get_owned_dossier(dossier_id)
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
            whois_summary=get_whois_summary(target_dir),
            nmap_summary=get_nmap_summary(target_dir),
            open_ports=get_open_ports(target_dir),
            osint_summary=get_osint_summary(target_dir),
            audit_logs=dossier.audit_logs,
        )

    @app.route("/dossier/<int:dossier_id>/export.<fmt>")
    @login_required
    def export_dossier(dossier_id, fmt):
        dossier = _get_owned_dossier(dossier_id)
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
        dossier = _get_owned_dossier(dossier_id)
        name = dossier.name
        target_dir = os.path.join(app.config["DOSSIER_DATA_DIR"], str(dossier.id))
        db.session.delete(dossier)
        db.session.commit()
        shutil.rmtree(target_dir, ignore_errors=True)
        # Dossier (and its audit rows) are gone; record a user-level entry.
        _audit("delete_dossier", dossier_id=None, detail=name)
        flash(f"Deleted dossier '{name}'", "success")
        return redirect(url_for("index"))

    # ------------------------------------------------------------- modules
    @app.route("/dossier/<int:dossier_id>/whois", methods=["POST"])
    @login_required
    def run_whois_query(dossier_id):
        dossier = _get_owned_dossier(dossier_id)
        target_dir = _dossier_data_dir(dossier.id)
        domain = request.form.get("domain")
        if not domain:
            flash("Domain is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        try:
            result = run_whois(domain, target_dir)
            if "error" in result:
                flash(f"WHOIS query failed: {result['error']}", "error")
            else:
                flash(f"WHOIS query completed for {domain}", "success")
                lists = _load_lists(target_dir)
                if domain not in lists["domains"]:
                    lists["domains"].append(domain)
                _save_lists(target_dir, lists)
            _audit("run_whois", dossier_id=dossier.id, detail=domain)
        except Exception as e:
            flash(f"WHOIS query failed: {str(e)}", "error")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/nmap", methods=["POST"])
    @login_required
    def run_nmap_scan_route(dossier_id):
        dossier = _get_owned_dossier(dossier_id)
        target_dir = _dossier_data_dir(dossier.id)
        target = request.form.get("target")
        scan_type = request.form.get("scan_type", "basic")
        if not target:
            flash("Target is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        try:
            result = run_nmap_scan(target, target_dir, scan_type)
            if "error" in result:
                flash(f"Nmap scan failed: {result['error']}", "error")
            else:
                flash(f"Nmap {scan_type} scan completed for {target}", "success")
                lists = _load_lists(target_dir)
                if target.replace(".", "").replace(":", "").isdigit() or ":" in target:
                    if target not in lists["ip_addresses"]:
                        lists["ip_addresses"].append(target)
                elif target not in lists["domains"]:
                    lists["domains"].append(target)
                _save_lists(target_dir, lists)
            _audit("run_nmap", dossier_id=dossier.id, detail=f"{scan_type}:{target}")
        except Exception as e:
            flash(f"Nmap scan failed: {str(e)}", "error")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/osint/social", methods=["POST"])
    @login_required
    def run_social_media_search(dossier_id):
        dossier = _get_owned_dossier(dossier_id)
        target_dir = _dossier_data_dir(dossier.id)
        target = request.form.get("target")
        if not target:
            flash("Target is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        try:
            search_social_media(target, target_dir)
            flash(f"Social media search completed for {target}", "success")
            _audit("run_social", dossier_id=dossier.id, detail=target)
        except Exception as e:
            flash(f"Social media search failed: {str(e)}", "error")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/osint/emails", methods=["POST"])
    @login_required
    def run_email_search(dossier_id):
        dossier = _get_owned_dossier(dossier_id)
        target_dir = _dossier_data_dir(dossier.id)
        domain = request.form.get("domain")
        if not domain:
            flash("Domain is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        try:
            result = search_emails(domain, target_dir)
            flash(f"Email search completed for {domain}", "success")
            lists = _load_lists(target_dir)
            for email in result.get("emails", []):
                if email not in lists["emails"]:
                    lists["emails"].append(email)
            _save_lists(target_dir, lists)
            _audit("run_emails", dossier_id=dossier.id, detail=domain)
        except Exception as e:
            flash(f"Email search failed: {str(e)}", "error")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/osint/breach", methods=["POST"])
    @login_required
    def run_breach_check(dossier_id):
        dossier = _get_owned_dossier(dossier_id)
        target_dir = _dossier_data_dir(dossier.id)
        email = request.form.get("email")
        if not email:
            flash("Email is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        try:
            check_breach_data(email, target_dir)
            flash(f"Breach check completed for {email}", "success")
            _audit("run_breach", dossier_id=dossier.id, detail=email)
        except Exception as e:
            flash(f"Breach check failed: {str(e)}", "error")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))

    @app.route("/dossier/<int:dossier_id>/osint/github", methods=["POST"])
    @login_required
    def run_github_search(dossier_id):
        dossier = _get_owned_dossier(dossier_id)
        target_dir = _dossier_data_dir(dossier.id)
        username = request.form.get("username")
        if not username:
            flash("Username is required", "error")
            return redirect(url_for("dossier_overview", dossier_id=dossier.id))
        try:
            search_github_info(username, target_dir)
            flash(f"GitHub search completed for {username}", "success")
            _audit("run_github", dossier_id=dossier.id, detail=username)
        except Exception as e:
            flash(f"GitHub search failed: {str(e)}", "error")
        return redirect(url_for("dossier_overview", dossier_id=dossier.id))


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, port=5001)
