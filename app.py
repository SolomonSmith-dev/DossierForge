from flask import Flask, render_template, request, redirect, url_for, flash
import os
import json
from modules.whois import run_whois, get_whois_summary
from modules.nmap import run_nmap_scan, get_nmap_summary, get_open_ports
from modules.osint import (
    search_social_media,
    search_emails,
    check_breach_data,
    search_github_info,
    get_osint_summary,
)

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY", "dev-key-change-in-prod"
)  # For flash messages
DOSSIERS_DIR = "dossiers"

os.makedirs(DOSSIERS_DIR, exist_ok=True)


@app.route("/")
def index():
    dossiers = [
        d
        for d in os.listdir(DOSSIERS_DIR)
        if os.path.isdir(os.path.join(DOSSIERS_DIR, d))
    ]
    return render_template("index.html", dossiers=dossiers)


@app.route("/dossier/new", methods=["GET", "POST"])
def new_dossier():
    if request.method == "POST":
        name = request.form["name"]
        target_dir = os.path.join(DOSSIERS_DIR, name)
        os.makedirs(target_dir, exist_ok=True)
        overview_path = os.path.join(target_dir, "overview.json")
        overview = {
            "name": name,
            "alias": request.form.get("alias", ""),
            "organization": request.form.get("organization", ""),
            "ip_addresses": [],
            "domains": [],
            "emails": [],
            "social_media": [],
        }
        with open(overview_path, "w") as f:
            json.dump(overview, f, indent=2)
        return redirect(url_for("dossier_overview", name=name))
    return render_template("new_dossier.html")


@app.route("/dossier/<name>")
def dossier_overview(name):
    target_dir = os.path.join(DOSSIERS_DIR, name)
    overview_path = os.path.join(target_dir, "overview.json")
    if not os.path.exists(overview_path):
        return "Dossier not found", 404
    with open(overview_path) as f:
        overview = json.load(f)

    # Get WHOIS summary if available
    whois_summary = get_whois_summary(target_dir)

    # Get nmap summary if available
    nmap_summary = get_nmap_summary(target_dir)
    open_ports = get_open_ports(target_dir)

    # Get OSINT summary if available
    osint_summary = get_osint_summary(target_dir)

    return render_template(
        "dossier_overview.html",
        overview=overview,
        name=name,
        whois_summary=whois_summary,
        nmap_summary=nmap_summary,
        open_ports=open_ports,
        osint_summary=osint_summary,
    )


@app.route("/dossier/<name>/whois", methods=["POST"])
def run_whois_query(name):
    target_dir = os.path.join(DOSSIERS_DIR, name)
    domain = request.form.get("domain")

    if not domain:
        flash("Domain is required", "error")
        return redirect(url_for("dossier_overview", name=name))

    try:
        result = run_whois(domain, target_dir)

        if "error" in result:
            flash(f"WHOIS query failed: {result['error']}", "error")
        else:
            flash(f"WHOIS query completed for {domain}", "success")

            # Update overview with domain info
            overview_path = os.path.join(target_dir, "overview.json")
            with open(overview_path) as f:
                overview = json.load(f)

            if domain not in overview["domains"]:
                overview["domains"].append(domain)

            with open(overview_path, "w") as f:
                json.dump(overview, f, indent=2)

    except Exception as e:
        flash(f"WHOIS query failed: {str(e)}", "error")

    return redirect(url_for("dossier_overview", name=name))


@app.route("/dossier/<name>/nmap", methods=["POST"])
def run_nmap_scan_route(name):
    target_dir = os.path.join(DOSSIERS_DIR, name)
    target = request.form.get("target")
    scan_type = request.form.get("scan_type", "basic")

    if not target:
        flash("Target is required", "error")
        return redirect(url_for("dossier_overview", name=name))

    try:
        result = run_nmap_scan(target, target_dir, scan_type)

        if "error" in result:
            flash(f"Nmap scan failed: {result['error']}", "error")
        else:
            flash(f"Nmap {scan_type} scan completed for {target}", "success")

            # Update overview with target info
            overview_path = os.path.join(target_dir, "overview.json")
            with open(overview_path) as f:
                overview = json.load(f)

            # Add target to IP addresses if it's an IP
            if target.replace(".", "").replace(":", "").isdigit() or ":" in target:
                if target not in overview["ip_addresses"]:
                    overview["ip_addresses"].append(target)
            else:
                # It's a hostname, add to domains
                if target not in overview["domains"]:
                    overview["domains"].append(target)

            with open(overview_path, "w") as f:
                json.dump(overview, f, indent=2)

    except Exception as e:
        flash(f"Nmap scan failed: {str(e)}", "error")

    return redirect(url_for("dossier_overview", name=name))


@app.route("/dossier/<name>/osint/social", methods=["POST"])
def run_social_media_search(name):
    target_dir = os.path.join(DOSSIERS_DIR, name)
    target = request.form.get("target")

    if not target:
        flash("Target is required", "error")
        return redirect(url_for("dossier_overview", name=name))

    try:
        search_social_media(target, target_dir)
        flash(f"Social media search completed for {target}", "success")

    except Exception as e:
        flash(f"Social media search failed: {str(e)}", "error")

    return redirect(url_for("dossier_overview", name=name))


@app.route("/dossier/<name>/osint/emails", methods=["POST"])
def run_email_search(name):
    target_dir = os.path.join(DOSSIERS_DIR, name)
    domain = request.form.get("domain")

    if not domain:
        flash("Domain is required", "error")
        return redirect(url_for("dossier_overview", name=name))

    try:
        result = search_emails(domain, target_dir)
        flash(f"Email search completed for {domain}", "success")

        # Update overview with found emails
        overview_path = os.path.join(target_dir, "overview.json")
        with open(overview_path) as f:
            overview = json.load(f)

        for email in result.get("emails", []):
            if email not in overview["emails"]:
                overview["emails"].append(email)

        with open(overview_path, "w") as f:
            json.dump(overview, f, indent=2)

    except Exception as e:
        flash(f"Email search failed: {str(e)}", "error")

    return redirect(url_for("dossier_overview", name=name))


@app.route("/dossier/<name>/osint/breach", methods=["POST"])
def run_breach_check(name):
    target_dir = os.path.join(DOSSIERS_DIR, name)
    email = request.form.get("email")

    if not email:
        flash("Email is required", "error")
        return redirect(url_for("dossier_overview", name=name))

    try:
        check_breach_data(email, target_dir)
        flash(f"Breach check completed for {email}", "success")

    except Exception as e:
        flash(f"Breach check failed: {str(e)}", "error")

    return redirect(url_for("dossier_overview", name=name))


@app.route("/dossier/<name>/osint/github", methods=["POST"])
def run_github_search(name):
    target_dir = os.path.join(DOSSIERS_DIR, name)
    username = request.form.get("username")

    if not username:
        flash("Username is required", "error")
        return redirect(url_for("dossier_overview", name=name))

    try:
        search_github_info(username, target_dir)
        flash(f"GitHub search completed for {username}", "success")

    except Exception as e:
        flash(f"GitHub search failed: {str(e)}", "error")

    return redirect(url_for("dossier_overview", name=name))


if __name__ == "__main__":
    app.run(debug=True, port=5001)
