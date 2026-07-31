"""Migration smoke tests.

Ensures the committed Alembic revision can build a fresh schema. Tests still
use create_all for speed; this verifies the migration path used in real runs.
"""

import os

from flask_migrate import upgrade as migrate_upgrade

from app import create_app
from models import db


def test_alembic_upgrade_creates_schema(tmp_path):
    db_path = tmp_path / "migrated.db"
    app = create_app(
        {
            "TESTING": False,
            "SECRET_KEY": "mig-test",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(db_path),
            "DOSSIER_DATA_DIR": str(tmp_path / "data"),
            "SKIP_DB_UPGRADE": True,  # apply explicitly below
        }
    )
    os.makedirs(app.config["DOSSIER_DATA_DIR"], exist_ok=True)
    with app.app_context():
        migrate_upgrade()
        tables = set(db.inspect(db.engine).get_table_names())
    expected = {
        "alembic_version",
        "users",
        "dossiers",
        "audit_logs",
        "dossier_shares",
        "notes",
        "tags",
        "scan_jobs",
        "organizations",
        "org_memberships",
        "dossier_org_access",
    }
    assert expected.issubset(tables)
