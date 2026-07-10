# AGENTS.md

## Cursor Cloud specific instructions

DossierForge is a multi-user Flask OSINT SaaS (Python). It uses Flask-Login for
auth and Flask-SQLAlchemy for persistence. Dossier metadata, users, and the audit
trail live in a SQL database (SQLite by default at `instance/dossierforge.db`,
Postgres-ready via `DATABASE_URL`); large recon artifacts are written to disk under
`instance/dossier_data/<dossier_id>/`. Standard setup/run commands live in
`README.md`; only non-obvious caveats are noted here.

### Architecture notes
- The app uses an application factory: `create_app(config)` in `app.py`. `app.py`
  also exposes a module-level `app = create_app()` so `python app.py` and
  `gunicorn "app:create_app()"` both work. Tests build their own app via the factory
  with a temp SQLite DB and temp `DOSSIER_DATA_DIR` (see `tests/conftest.py`).
- The DB schema is created automatically on startup via `db.create_all()`. There are
  no migrations yet, so if you change `models.py`, delete `instance/dossierforge.db`
  (dev only) to recreate it.
- The `instance/` folder (DB + recon artifacts) is gitignored; deleting it resets all
  local users and dossiers.
- Product guardrail: creating a dossier requires an authorized-use attestation
  (`authorized` checkbox) and every recon action is written to `AuditLog`. Keep these
  when adding new recon routes.

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
