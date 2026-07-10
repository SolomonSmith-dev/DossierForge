# DossierForge

![CI](https://github.com/SolomonSmith-dev/DossierForge/actions/workflows/ci.yml/badge.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg) ![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

A Flask-based multi-user OSINT dossier SaaS for aggregating reconnaissance data on a target. Sign up, create per-target dossiers, and run WHOIS lookups, nmap port scans, and social media/email searches. Everything is stored in a structured, per-user dossier for review. Each dossier requires an authorized-use attestation, and every recon action is written to an audit trail.

> **Authorized use only.** This tool is for security research, CTF practice, and reconnaissance against targets you own or have explicit written permission to scan. Running unsolicited scans or OSINT enumeration against third parties is illegal in most jurisdictions and a hard line. Use a personal lab, an HTB box, or your employer's authorized scope.

## Problem

Security researchers and pentesters spend the first hour of any engagement running the same five tools, pasting outputs into a notes file, and trying to keep target context straight when juggling several engagements at once. DossierForge collapses that into a single Flask app: pick a target, fire the modules you need, and review a per-target dossier with all collected artifacts in one place.

## Features

- Multi-user accounts: register, sign in, and keep dossiers isolated per user
- Authorized-use attestation: creating a dossier requires confirming authorization; the attestation and scope are recorded
- Audit trail: every dossier action and recon run is logged per dossier
- WHOIS lookup: domain registration data, registrar, nameservers, expiry
- nmap scanning: port scan with service detection and open-port summary
- OSINT modules: social media search, email enumeration, breach check, GitHub info
- Dossier management: create, organize, and browse target profiles via web UI

## Stack

- Python 3.8+, Flask (app factory in `create_app()`)
- Flask-Login (auth), Flask-SQLAlchemy (ORM)
- Database: SQLite in dev (`instance/dossierforge.db`), Postgres-ready via `DATABASE_URL`
- `python-whois`, `nmap` (system binary), `requests`
- Jinja2 templates; recon artifacts stored on disk under `instance/dossier_data/<id>/`
- gunicorn for production serving

## Quickstart

Requires Python 3.8+ and the `nmap` binary installed on your system (`brew install nmap` or `apt install nmap`).

```bash
git clone https://github.com/SolomonSmith-dev/DossierForge
cd DossierForge

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env: at minimum set SECRET_KEY
```

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | yes | Random string used to sign Flask sessions |
| `DATABASE_URL` | no | SQLAlchemy database URL (defaults to SQLite under `instance/`). Use `postgresql://...` for Postgres |
| `DOSSIER_DATA_DIR` | no | Directory for recon artifacts (defaults to `instance/dossier_data`) |
| `GITHUB_TOKEN` | no | GitHub PAT for higher API rate limits (used in GitHub lookups) |
| `NMAP_PATH` | no | Absolute path to `nmap` if not on `$PATH` |

See `.env.example` for a template.

### Run

```bash
# Load env vars from .env and start the dev server
set -a
. ./.env
set +a

python app.py
# or use the helper script (respects your active virtualenv)
bash start_app.sh
```

Open `http://localhost:5001` in your browser. The database and instance folder are
created automatically on first run.

For production, serve the app factory with gunicorn:

```bash
gunicorn "app:create_app()" --bind 0.0.0.0:5001
```

## Usage

1. Sign up for an account (or sign in). Dossiers are private to your account.
2. Create a new dossier. Enter a target name, alias, and organization, and confirm
   the authorized-use attestation (with an optional scope/reference).
3. Run modules against the target (WHOIS, nmap, OSINT). Each module appends its
   results to the dossier and records an entry in the audit trail.
4. Review aggregated results and the audit trail on the dossier overview page.

## Modules

| Module | What it does |
|---|---|
| `modules/whois.py` | WHOIS lookup and summary extraction |
| `modules/nmap.py` | Port scan, service detection, open-port list |
| `modules/osint.py` | Social media search, email search, breach check, GitHub info |

## Project structure

```
.
├── app.py                # Flask app factory, auth, routes
├── models.py             # SQLAlchemy models (User, Dossier, AuditLog)
├── modules/              # WHOIS, nmap, OSINT recon modules
├── templates/            # Jinja2 templates (base, auth, dossier views)
├── instance/             # SQLite DB + recon artifacts (gitignored)
├── tests/
├── start_app.sh
├── requirements.txt
└── README.md
```

## Roadmap

- [ ] Background job queue for long-running scans
- [ ] CSV/Markdown export of dossiers
- [ ] Optional Postgres backend for multi-user setups

## License

MIT. See `LICENSE`.

## Author

Solomon Smith. solomonsmithdev@gmail.com
