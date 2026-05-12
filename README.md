# DossierForge

![CI](https://github.com/SolomonSmith-dev/DossierForge/actions/workflows/ci.yml/badge.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg) ![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

A Flask-based OSINT dossier builder for aggregating reconnaissance data on a target. Input a name, domain, or IP. DossierForge runs WHOIS lookups, nmap port scans, and social media/email searches, then stores everything in a structured dossier for review.

> **Authorized use only.** This tool is for security research, CTF practice, and reconnaissance against targets you own or have explicit written permission to scan. Running unsolicited scans or OSINT enumeration against third parties is illegal in most jurisdictions and a hard line. Use a personal lab, an HTB box, or your employer's authorized scope.

## Problem

Security researchers and pentesters spend the first hour of any engagement running the same five tools, pasting outputs into a notes file, and trying to keep target context straight when juggling several engagements at once. DossierForge collapses that into a single Flask app: pick a target, fire the modules you need, and review a per-target dossier with all collected artifacts in one place.

## Features

- WHOIS lookup: domain registration data, registrar, nameservers, expiry
- nmap scanning: port scan with service detection and open-port summary
- OSINT modules: social media search, email enumeration, breach check, GitHub info
- Dossier management: create, organize, and browse target profiles via web UI
- Persistent storage: each dossier saved as structured JSON for later review

## Stack

- Python 3.8+, Flask
- `python-whois`, `nmap` (system binary), `requests`
- Jinja2 templates
- JSON file-based storage (one file per dossier)

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

Open `http://localhost:5001` in your browser.

## Usage

1. Create a new dossier. Enter a target name, alias, and organization.
2. Run modules against the target (WHOIS, nmap, OSINT). Each module appends its results to the dossier.
3. Review aggregated results on the dossier overview page. Export the JSON for downstream tooling if needed.

## Modules

| Module | What it does |
|---|---|
| `modules/whois.py` | WHOIS lookup and summary extraction |
| `modules/nmap.py` | Port scan, service detection, open-port list |
| `modules/osint.py` | Social media search, email search, breach check, GitHub info |

## Project structure

```
.
├── app.py                # Flask entry point
├── modules/              # WHOIS, nmap, OSINT recon modules
├── templates/            # Jinja2 templates
├── dossiers/             # per-target JSON storage (gitignored in practice)
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
