"""
ROUTE TESTS — test Flask endpoints return correct responses.

WHY: Route tests verify your app handles requests correctly.
We mock external calls (WHOIS, nmap, OSINT) so tests are fast
and don't depend on external services or tools being available.

PATTERN: "mock external dependency" — replace real network calls
with fake responses so tests are reliable and fast.
"""

from unittest.mock import patch


def test_index_returns_200(client):
    """
    SMOKE TEST — does the main page load?

    ARRANGE: nothing (client fixture handles setup)
    ACT: GET /
    ASSERT: 200 status
    """
    response = client.get("/")
    assert response.status_code == 200


def test_new_dossier_get_returns_200(client):
    """
    Does the new dossier form render?
    """
    response = client.get("/dossier/new")
    assert response.status_code == 200


def test_new_dossier_post_creates_dossier(client, tmp_path):
    """
    INTEGRATION TEST — does creating a dossier work end-to-end?

    ARRANGE: form data with a dossier name
    ACT: POST to /dossier/new
    ASSERT: redirects (302) and dossier directory + overview.json exist
    """
    response = client.post(
        "/dossier/new",
        data={"name": "test-target", "alias": "TT", "organization": "TestCorp"},
        follow_redirects=False,
    )
    # Should redirect to the dossier overview
    assert response.status_code == 302

    # Verify the dossier was created on disk
    import json

    overview_path = tmp_path / "test-target" / "overview.json"
    assert overview_path.exists()
    overview = json.loads(overview_path.read_text())
    assert overview["name"] == "test-target"
    assert overview["alias"] == "TT"
    assert overview["organization"] == "TestCorp"


@patch("app.get_whois_summary", return_value=None)
@patch("app.get_nmap_summary", return_value=None)
@patch("app.get_open_ports", return_value=[])
@patch("app.get_osint_summary", return_value=None)
def test_dossier_overview_returns_200(
    mock_osint, mock_ports, mock_nmap, mock_whois, client, tmp_path
):
    """
    Does the dossier overview page load for an existing dossier?

    WHY: This route reads from disk and calls summary functions.
    We mock all summary functions to avoid needing real scan data.
    """
    import json

    # ARRANGE: create a dossier on disk
    dossier_dir = tmp_path / "test-target"
    dossier_dir.mkdir()
    overview = {"name": "test-target", "alias": "", "organization": ""}
    (dossier_dir / "overview.json").write_text(json.dumps(overview))

    # ACT
    response = client.get("/dossier/test-target")

    # ASSERT
    assert response.status_code == 200


def test_dossier_overview_returns_404_for_missing(client):
    """
    Does the app return 404 for a nonexistent dossier?
    """
    response = client.get("/dossier/nonexistent")
    assert response.status_code == 404
