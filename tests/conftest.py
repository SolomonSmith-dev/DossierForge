"""
FIXTURES — shared test setup for DossierForge tests.

WHY: Flask provides a test client that simulates HTTP requests
without starting a real server. This fixture creates that client
so every test can use it.

PATTERN: "test client" — Flask's built-in way to test routes.
"""

import pytest
import sys
import os

# Add project root to path so we can import app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create a Flask test client with isolated dossier directory.

    Uses tmp_path so tests don't write to the real dossiers/ folder.
    """
    app.config["TESTING"] = True
    monkeypatch.setattr("app.DOSSIERS_DIR", str(tmp_path))
    with app.test_client() as client:
        yield client
