"""Shared test fixtures for DossierForge.

Builds an isolated app instance per test with a temporary SQLite database and
dossier data directory, so tests never touch real user data.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app  # noqa: E402


@pytest.fixture
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(tmp_path / "test.db"),
            "DOSSIER_DATA_DIR": str(tmp_path / "data"),
            # Run scan jobs inline so tests are deterministic (no worker thread).
            "SCAN_JOBS_EAGER": True,
        }
    )
    os.makedirs(application.config["DOSSIER_DATA_DIR"], exist_ok=True)
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, email="user@example.com", password="password123"):
    """Register a new account; the client is left logged in."""
    return client.post(
        "/register",
        data={"email": email, "password": password},
        follow_redirects=True,
    )
