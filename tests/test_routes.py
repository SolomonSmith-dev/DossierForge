"""Route tests for DossierForge.

Covers auth gating, the authorized-use attestation gate, per-user data
isolation, and audit logging. External recon calls are exercised through the
offline breach-check module so no network or system binaries are required.
"""

from conftest import register

from models import (
    AuditLog,
    Dossier,
    DossierShare,
    Note,
    Organization,
    OrgMembership,
    ScanJob,
    Tag,
    User,
    db,
)


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
    assert b"Queued breach check" in resp.data
    with app.app_context():
        logs = db.session.query(AuditLog).filter_by(action="run_breach").all()
        assert len(logs) == 1
        assert logs[0].detail == "demo@example.com"
        job = db.session.query(ScanJob).filter_by(module="breach").one()
        assert job.status == "success"
        assert "demo@example.com" in job.message


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


def _two_users(app, second_email="teammate@example.com"):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    dossier_id = _make_dossier(owner, app, name="Shared Case")
    teammate = app.test_client()
    register(teammate, email=second_email)
    return owner, teammate, dossier_id


def test_share_grants_viewer_read_only_access(app):
    owner, viewer, dossier_id = _two_users(app)
    # No access before sharing.
    assert viewer.get(f"/dossier/{dossier_id}").status_code == 404

    owner.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "teammate@example.com", "role": "viewer"},
    )
    # Viewer can read and export...
    assert viewer.get(f"/dossier/{dossier_id}").status_code == 200
    assert viewer.get(f"/dossier/{dossier_id}/export.md").status_code == 200
    # ...but cannot run modules (edit) or delete/share (owner).
    assert (
        viewer.post(
            f"/dossier/{dossier_id}/osint/breach", data={"email": "x@y.com"}
        ).status_code
        == 403
    )
    assert viewer.post(f"/dossier/{dossier_id}/delete").status_code == 404
    assert (
        viewer.post(
            f"/dossier/{dossier_id}/share", data={"email": "z@z.com"}
        ).status_code
        == 404
    )


def test_editor_can_run_modules_but_not_delete(app):
    owner, editor, dossier_id = _two_users(app)
    owner.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "teammate@example.com", "role": "editor"},
    )
    resp = editor.post(
        f"/dossier/{dossier_id}/osint/breach",
        data={"email": "demo@example.com"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Queued breach check" in resp.data
    # Editor still cannot delete.
    assert editor.post(f"/dossier/{dossier_id}/delete").status_code == 404


def test_share_requires_existing_account(app):
    owner, _teammate, dossier_id = _two_users(app)
    owner.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "nobody@nowhere.com", "role": "viewer"},
        follow_redirects=True,
    )
    with app.app_context():
        assert db.session.query(DossierShare).count() == 0


def test_unshare_revokes_access(app):
    owner, viewer, dossier_id = _two_users(app)
    owner.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "teammate@example.com", "role": "viewer"},
    )
    with app.app_context():
        share_id = db.session.query(DossierShare).one().id
    assert viewer.get(f"/dossier/{dossier_id}").status_code == 200

    owner.post(f"/dossier/{dossier_id}/unshare", data={"share_id": share_id})
    assert viewer.get(f"/dossier/{dossier_id}").status_code == 404


def test_shared_dossier_appears_on_dashboard(app):
    owner, viewer, dossier_id = _two_users(app)
    owner.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "teammate@example.com", "role": "viewer"},
    )
    resp = viewer.get("/")
    assert resp.status_code == 200
    assert b"Shared with you" in resp.data
    assert b"Shared Case" in resp.data


def test_add_note_and_edit_access(app):
    owner, viewer, dossier_id = _two_users(app)
    owner.post(f"/dossier/{dossier_id}/notes", data={"body": "Found exposed admin"})
    with app.app_context():
        note = db.session.query(Note).one()
        assert note.body == "Found exposed admin"
        assert db.session.query(AuditLog).filter_by(action="add_note").count() == 1

    # Viewer (read-only) cannot add notes.
    owner.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "teammate@example.com", "role": "viewer"},
    )
    assert (
        viewer.post(f"/dossier/{dossier_id}/notes", data={"body": "nope"}).status_code
        == 403
    )


def test_add_tag_dedupes_and_powers_search(client, app):
    register(client)
    dossier_id = _make_dossier(client, app, name="Acme")
    client.post(f"/dossier/{dossier_id}/tags", data={"name": "Phishing"})
    client.post(f"/dossier/{dossier_id}/tags", data={"name": "phishing"})  # dup
    with app.app_context():
        tags = db.session.query(Tag).all()
        assert len(tags) == 1
        assert tags[0].name == "phishing"

    # Search by tag returns the dossier; a non-matching query does not.
    assert b"Acme" in client.get("/?q=phish").data
    assert b"Acme" not in client.get("/?q=zzzzz").data


def test_scan_job_recorded_and_shown_on_overview(client, app):
    register(client)
    dossier_id = _make_dossier(client, app, name="Acme")
    client.post(
        f"/dossier/{dossier_id}/osint/breach", data={"email": "demo@example.com"}
    )
    with app.app_context():
        job = db.session.query(ScanJob).one()
        assert job.module == "breach"
        assert job.status == "success"
        assert job.finished_at is not None
    # The Scan Jobs panel surfaces the completed job.
    page = client.get(f"/dossier/{dossier_id}").data
    assert b"Scan Jobs" in page
    assert b"success" in page


def test_notes_and_tags_in_export(client, app):
    register(client)
    dossier_id = _make_dossier(client, app, name="Acme")
    client.post(f"/dossier/{dossier_id}/tags", data={"name": "engagement-7"})
    client.post(
        f"/dossier/{dossier_id}/notes", data={"body": "Credentials leaked on pastebin"}
    )
    md = client.get(f"/dossier/{dossier_id}/export.md").data
    assert b"engagement-7" in md
    assert b"Credentials leaked on pastebin" in md
    assert b"## Notes" in md


def _create_org(client, app, name="Acme Team"):
    client.post("/orgs", data={"name": name})
    with app.app_context():
        return db.session.query(Organization).filter_by(name=name).one().id


def test_create_org_makes_creator_admin(client, app):
    register(client, email="owner@example.com")
    org_id = _create_org(client, app)
    with app.app_context():
        m = db.session.query(OrgMembership).filter_by(org_id=org_id).one()
        assert m.role == "admin"


def test_org_share_grants_member_editor_access(app):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    dossier_id = _make_dossier(owner, app, name="Team Case")
    org_id = _create_org(owner, app)

    member = app.test_client()
    register(member, email="member@example.com")

    # Non-member cannot see the dossier.
    assert member.get(f"/dossier/{dossier_id}").status_code == 404

    owner.post(f"/orgs/{org_id}/members", data={"email": "member@example.com"})
    owner.post(
        f"/dossier/{dossier_id}/org-share",
        data={"org_id": org_id, "role": "editor"},
    )

    # Member now has editor access via the org: can view and run modules.
    assert member.get(f"/dossier/{dossier_id}").status_code == 200
    resp = member.post(
        f"/dossier/{dossier_id}/osint/breach",
        data={"email": "x@y.com"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Queued breach check" in resp.data


def test_org_viewer_role_is_read_only(app):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    dossier_id = _make_dossier(owner, app, name="Team Case")
    org_id = _create_org(owner, app)
    member = app.test_client()
    register(member, email="member@example.com")
    owner.post(f"/orgs/{org_id}/members", data={"email": "member@example.com"})
    owner.post(
        f"/dossier/{dossier_id}/org-share",
        data={"org_id": org_id, "role": "viewer"},
    )
    assert member.get(f"/dossier/{dossier_id}").status_code == 200
    assert (
        member.post(
            f"/dossier/{dossier_id}/osint/breach", data={"email": "x@y.com"}
        ).status_code
        == 403
    )


def test_removing_member_revokes_org_access(app):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    dossier_id = _make_dossier(owner, app, name="Team Case")
    org_id = _create_org(owner, app)
    member = app.test_client()
    register(member, email="member@example.com")
    owner.post(f"/orgs/{org_id}/members", data={"email": "member@example.com"})
    owner.post(
        f"/dossier/{dossier_id}/org-share",
        data={"org_id": org_id, "role": "viewer"},
    )
    assert member.get(f"/dossier/{dossier_id}").status_code == 200

    with app.app_context():
        member_user_id = (
            db.session.query(User).filter_by(email="member@example.com").one().id
        )
    owner.post(f"/orgs/{org_id}/members/{member_user_id}/remove")
    assert member.get(f"/dossier/{dossier_id}").status_code == 404


def test_non_admin_cannot_add_members(app):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    org_id = _create_org(owner, app)
    member = app.test_client()
    register(member, email="member@example.com")
    owner.post(f"/orgs/{org_id}/members", data={"email": "member@example.com"})
    # Member (non-admin) cannot add others.
    assert (
        member.post(
            f"/orgs/{org_id}/members", data={"email": "someone@example.com"}
        ).status_code
        == 403
    )


def test_org_shared_dossier_on_member_dashboard(app):
    owner = app.test_client()
    register(owner, email="owner@example.com")
    dossier_id = _make_dossier(owner, app, name="Team Case")
    org_id = _create_org(owner, app)
    member = app.test_client()
    register(member, email="member@example.com")
    owner.post(f"/orgs/{org_id}/members", data={"email": "member@example.com"})
    owner.post(
        f"/dossier/{dossier_id}/org-share",
        data={"org_id": org_id, "role": "viewer"},
    )
    resp = member.get("/")
    assert b"Shared with you" in resp.data
    assert b"Team Case" in resp.data


def test_edit_dossier_updates_metadata(client, app):
    register(client)
    dossier_id = _make_dossier(client, app, name="Old Name")
    resp = client.post(
        f"/dossier/{dossier_id}/edit",
        data={
            "name": "New Name",
            "alias": "nn",
            "organization": "NewOrg",
            "authorization_scope": "SOW-99",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Dossier updated" in resp.data
    assert b"New Name" in resp.data
    assert b"SOW-99" in resp.data
    with app.app_context():
        dossier = db.session.get(Dossier, dossier_id)
        assert dossier.name == "New Name"
        assert dossier.alias == "nn"
        assert dossier.organization == "NewOrg"
        assert dossier.authorization_scope == "SOW-99"
        assert db.session.query(AuditLog).filter_by(action="edit_dossier").count() == 1


def test_edit_dossier_is_owner_only(app):
    owner, viewer, dossier_id = _two_users(app)
    owner.post(
        f"/dossier/{dossier_id}/share",
        data={"email": "teammate@example.com", "role": "editor"},
    )
    # Even editors cannot edit dossier metadata.
    assert viewer.get(f"/dossier/{dossier_id}/edit").status_code == 404
    assert (
        viewer.post(
            f"/dossier/{dossier_id}/edit", data={"name": "Hijacked"}
        ).status_code
        == 404
    )
    with app.app_context():
        assert db.session.get(Dossier, dossier_id).name == "Shared Case"
