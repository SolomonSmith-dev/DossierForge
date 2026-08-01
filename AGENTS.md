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
- Invitations (`Invitation` model): org admins and dossier owners can invite by
  email even when the invitee has no account. Existing accounts are granted access
  immediately; otherwise the invite stays `pending`, an email is sent via
  `modules/mail.py` (`MAIL_BACKEND=console|memory|smtp`), and access is claimed on
  register/login (`_claim_pending_invites`) or via `/invite/<token>`. Revoke with
  `POST /invites/<id>/revoke`. Default backend is `console` (prints to stdout);
  tests use `memory`. Set `MAIL_SERVER` + `MAIL_BACKEND=smtp` for real delivery.
  Generating a new revision after model changes:
  `SKIP_DB_UPGRADE=1 flask --app "app:create_app" db migrate -m "..."`.
- The `instance/` folder (DB + recon artifacts) is gitignored; deleting it resets all
  local users and dossiers (migrations will recreate the schema on next start).
- Product guardrail: creating a dossier requires an authorized-use attestation
  (`authorized` checkbox) and every recon action is written to `AuditLog`. Keep these
  when adding new recon routes. Dossier metadata edits (`/dossier/<id>/edit`) are
  owner-only so the authorization scope stays under the owner's control.
- Access control: use `_get_dossier_access(dossier_id, need=...)` in `app.py` for all
  dossier routes. `need` is `"view"` (owner or any collaborator), `"edit"` (owner or
  editor collaborator; recon/module routes), or `"owner"` (owner-only; delete/share/edit
  metadata). It returns `(dossier, role)`; no-access is 404 and insufficient-role is 403.
  A user's effective non-owner role (`_effective_shared_role`) is the best of any direct
  `DossierShare` and any `DossierOrgAccess` for orgs they belong to (editor beats
  viewer). Organizations (`Organization`/`OrgMembership`) grant team-wide access;
  use `_get_org_membership(org_id, need_admin=...)` for org routes.
- Dossier report export (`modules/export.py`) is a pure renderer; the report dict is
  assembled in `app.py:_build_report` from DB metadata (incl. notes/tags) plus on-disk
  recon summaries. Add new sections in both places.
- Recon runs are asynchronous: routes insert a `ScanJob` (`queued`) and return
  immediately. A durable in-process poller (`_scan_worker_loop` in `app.py`) claims
  jobs from the DB and runs `_execute_scan_job`. On startup it reclaims orphaned
  `running` rows back to `queued` so a crash/restart does not lose work. The
  overview page auto-refreshes only while a job is pending. Set `SCAN_JOBS_EAGER=true`
  to run jobs inline (tests rely on this). Disable the poller with
  `SCAN_WORKER_ENABLED=false`. Multi-process gunicorn: each process may run a poller;
  claim uses a conditional UPDATE so only one worker wins a given job.
- Lint rules are pinned in `ruff.toml` (`select = ["E4","E7","E9","F"]`) so results are
  stable across ruff versions (newer ruff broadened its defaults and flagged the
  pre-existing recon modules). Keep this file; the update script installs ruff unpinned.

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
