"""Tests for outbound invitation email."""

from conftest import register

from models import Invitation, Organization, db
from modules.mail import get_outbox


def _make_dossier(client, app, name="Case"):
    from models import Dossier

    client.post("/dossier/new", data={"name": name, "authorized": "yes"})
    with app.app_context():
        return db.session.query(Dossier).filter_by(name=name).one().id


def test_pending_dossier_invite_sends_email(client, app):
    register(client, email="owner@example.com")
    dossier_id = _make_dossier(client, app, name="Email Case")
    resp = client.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "newbie@example.com", "role": "viewer"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Invitation emailed" in resp.data

    outbox = get_outbox()
    assert len(outbox) == 1
    mail = outbox[0]
    assert mail["to"] == "newbie@example.com"
    assert "invited" in mail["subject"].lower()
    assert "/invite/" in mail["text"]
    with app.app_context():
        invite = (
            db.session.query(Invitation).filter_by(email="newbie@example.com").one()
        )
        assert invite.token in mail["text"]
        assert invite.token in mail["html"]


def test_existing_user_share_does_not_email(client, app):
    register(client, email="owner@example.com")
    other = app.test_client()
    register(other, email="teammate@example.com")
    dossier_id = _make_dossier(client, app)
    before = len(get_outbox())
    client.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "teammate@example.com", "role": "editor"},
    )
    assert len(get_outbox()) == before


def test_pending_org_invite_sends_email(client, app):
    register(client, email="admin@example.com")
    client.post("/orgs", data={"name": "Mail Org"})
    with app.app_context():
        org_id = db.session.query(Organization).filter_by(name="Mail Org").one().id
    resp = client.post(
        f"/orgs/{org_id}/members",
        data={"email": "hire@example.com", "role": "member"},
        follow_redirects=True,
    )
    assert b"Invitation emailed" in resp.data
    outbox = get_outbox()
    assert any(
        m["to"] == "hire@example.com" and "Mail Org" in m["text"] for m in outbox
    )
