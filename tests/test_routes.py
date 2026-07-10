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
