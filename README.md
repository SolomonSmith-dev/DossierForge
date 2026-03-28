# DossierForge

A Flask-based OSINT dossier builder for aggregating reconnaissance data on a target. Input a name, domain, or IP — DossierForge runs WHOIS lookups, nmap port scans, and social media/email searches, then stores everything in a structured dossier for review.

Built for security research and reconnaissance workflows.

## Features

- **WHOIS lookup** — domain registration data, registrar, nameservers, expiry
- **nmap scanning** — port scanning with service detection and open port summary
- **OSINT modules** — social media search, email enumeration, breach data check, GitHub info
- **Dossier management** — create, organize, and browse target profiles via web UI
- **Persistent storage** — each dossier stored as structured JSON for later review

## Stack

- Python, Flask
- python-whois, nmap (system), requests
- Jinja2 templates
- JSON file-based storage

## Setup

**Requirements:** Python 3.8+, nmap installed on your system

```bash
# Clone the repo
git clone https://github.com/SolomonSmith-dev/DossierForge
cd DossierForge

# Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Copy the example env file and fill in your values
cp .env.example .env
# Edit .env — at minimum set SECRET_KEY
```

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | **Yes** | Random string used to sign Flask sessions |
| `HIBP_API_KEY` | No | HaveIBeenPwned API key for real breach lookups |
| `GITHUB_TOKEN` | No | GitHub PAT for higher GitHub API rate limits |
| `NMAP_PATH` | No | Absolute path to `nmap` if not on `$PATH` |

See `.env.example` for a template.

### Run

```bash
# Load env vars and start the dev server
export $(grep -v '^#' .env | xargs)
python app.py
# or use the provided helper script
bash start_app.sh
```

Open `http://localhost:5001` in your browser.

## Usage

1. Create a new dossier — enter a target name, alias, organization
2. Run modules against the target (WHOIS, nmap, OSINT)
3. Review aggregated results on the dossier overview page

## Modules

| Module | What It Does |
|--------|-------------|
| `whois.py` | WHOIS lookup and summary extraction |
| `nmap.py` | Port scan, service detection, open port list |
| `osint.py` | Social media search, email search, breach check, GitHub info |

## Disclaimer

For authorized security research and educational use only. Do not use against targets you do not have permission to scan.

## License

MIT
