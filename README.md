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

# Install Python dependencies
pip install -r requirements.txt

# Set a secret key (required for Flask sessions)
export SECRET_KEY=your-secret-key

# Run
python app.py
# or
bash start_app.sh
```

Open `http://localhost:5000` in your browser.

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
