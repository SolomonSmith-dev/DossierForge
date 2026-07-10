# AGENTS.md

## Cursor Cloud specific instructions

DossierForge is a single Flask OSINT web app (Python). There is no database; each
dossier is stored as JSON files under `dossiers/` (gitignored). Standard setup/run
commands live in `README.md`; only non-obvious caveats are noted here.

### Environment
- Dependencies are installed into a virtualenv at `.venv/` (the update script creates
  it and installs `requirements.txt` plus `pytest`, `pytest-cov`, `ruff`). Run tools
  via `.venv/bin/<tool>` or activate with `source .venv/bin/activate`.

### Run / lint / test
- Run the dev server: `.venv/bin/python app.py`. The port is **hardcoded to 5001** in
  `app.py` (and `start_app.sh`) with `debug=True` — there is no CLI flag to change it.
- `start_app.sh start|stop|restart|status` manages the server; note `start` kills any
  process already listening on 5001 (via `lsof`), so don't run it if you want to keep
  an existing server.
- Lint (matches CI): `.venv/bin/ruff check .` and `.venv/bin/ruff format --check .`
- Tests: `.venv/bin/pytest tests/ -v --cov`. The suite is fully offline — all recon
  calls (WHOIS/nmap/OSINT) are mocked and no network/binaries are required.

### Feature caveats
- `SECRET_KEY` is optional locally: `app.py` falls back to a dev key. It only signs
  flash/session cookies.
- The `nmap` and `whois` system binaries are NOT installed by the update script. The
  WHOIS and nmap module routes will fail without them; install `nmap`/`whois` and have
  network access only if you need to exercise those features.
- The breach-check OSINT module is mocked and works offline (good for smoke tests);
  the social/email/GitHub OSINT modules make real outbound HTTP calls.
- `GITHUB_TOKEN` and `NMAP_PATH` appear in `.env.example`/README but are not referenced
  in the code.
