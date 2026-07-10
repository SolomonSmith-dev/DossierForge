"""Route tests for DossierForge.

Covers auth gating, the authorized-use attestation gate, per-user data
isolation, and audit logging. External recon calls are exercised through the
offline breach-check module so no network or system binaries are required.
"""

from conftest import register

from models import AuditLog, Dossier, User, db


def test_index_requires_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_register_creates_user_and_logs_in(client, app):
    response = register(client)
    assert response.status_code == 200
    with app.app_context():
        assert db.session.query(User).filter_by(email="user@example.com").first()


def test_new_dossier_requires_attestation(client, app):
    register(client)
    # Without the authorized checkbox the dossier must NOT be created.
    resp = client.post(
        "/dossier/new",
        data={"name": "acme", "alias": "a", "organization": "Acme"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app.app_context():
        assert db.session.query(Dossier).count() == 0

    # With attestation it is created and redirects to the overview.
    resp = client.post(
        "/dossier/new",
        data={"name": "acme", "authorized": "yes", "authorization_scope": "SOW-1"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    with app.app_context():
        dossier = db.session.query(Dossier).one()
        assert dossier.name == "acme"
        assert dossier.authorization_scope == "SOW-1"


def test_dossiers_are_isolated_per_user(app):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    owner.post("/dossier/new", data={"name": "secret", "authorized": "yes"})
    with app.app_context():
        dossier_id = db.session.query(Dossier).one().id

    # A different user must not be able to view it.
    intruder = app.test_client()
    register(intruder, email="intruder@example.com")
    resp = intruder.get(f"/dossier/{dossier_id}")
    assert resp.status_code == 404


def test_run_breach_module_records_audit(client, app):
    register(client)
    client.post("/dossier/new", data={"name": "acme", "authorized": "yes"})
    with app.app_context():
        dossier_id = db.session.query(Dossier).one().id

    resp = client.post(
        f"/dossier/{dossier_id}/osint/breach",
        data={"email": "demo@example.com"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Breach check completed" in resp.data
    with app.app_context():
        logs = db.session.query(AuditLog).filter_by(action="run_breach").all()
        assert len(logs) == 1
        assert logs[0].detail == "demo@example.com"


def test_overview_returns_200_for_owner(client, app):
    register(client)
    client.post("/dossier/new", data={"name": "acme", "authorized": "yes"})
    with app.app_context():
        dossier_id = db.session.query(Dossier).one().id
    resp = client.get(f"/dossier/{dossier_id}")
    assert resp.status_code == 200
    assert b"acme" in resp.data


def test_overview_404_for_missing(client):
    register(client)
    assert client.get("/dossier/999999").status_code == 404


def _make_dossier(client, app, name="acme"):
    client.post("/dossier/new", data={"name": name, "authorized": "yes"})
    with app.app_context():
        return db.session.query(Dossier).filter_by(name=name).one().id


def test_export_markdown_and_json(client, app):
    register(client)
    dossier_id = _make_dossier(client, app, name="Acme Corp")
    client.post(
        f"/dossier/{dossier_id}/osint/breach", data={"email": "demo@example.com"}
    )

    md = client.get(f"/dossier/{dossier_id}/export.md")
    assert md.status_code == 200
    assert md.mimetype == "text/markdown"
    assert b"# Dossier Report: Acme Corp" in md.data
    assert b"## Authorized use" in md.data
    assert b"## Audit trail" in md.data
    assert "attachment" in md.headers["Content-Disposition"]

    js = client.get(f"/dossier/{dossier_id}/export.json")
    assert js.status_code == 200
    assert js.mimetype == "application/json"
    import json as _json

    payload = _json.loads(js.data)
    assert payload["name"] == "Acme Corp"
    assert any(a["action"] == "run_breach" for a in payload["audit"])


def test_export_is_isolated(app):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    dossier_id = _make_dossier(owner, app, name="secret")

    intruder = app.test_client()
    register(intruder, email="intruder@example.com")
    assert intruder.get(f"/dossier/{dossier_id}/export.md").status_code == 404


def test_delete_dossier(client, app):
    register(client)
    dossier_id = _make_dossier(client, app)
    resp = client.post(f"/dossier/{dossier_id}/delete", follow_redirects=False)
    assert resp.status_code == 302
    with app.app_context():
        assert db.session.get(Dossier, dossier_id) is None
        assert (
            db.session.query(AuditLog).filter_by(action="delete_dossier").count() == 1
        )


def test_delete_is_isolated(app):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    dossier_id = _make_dossier(owner, app, name="secret")

    intruder = app.test_client()
    register(intruder, email="intruder@example.com")
    assert intruder.post(f"/dossier/{dossier_id}/delete").status_code == 404
    with app.app_context():
        assert db.session.get(Dossier, dossier_id) is not None
