"""Durable DB-backed scan worker: reclaim, claim, and process queued jobs."""

import os

from conftest import register

from app import (
    claim_next_scan_job,
    process_one_queued_scan,
    reclaim_orphaned_scan_jobs,
)
from models import ScanJob, User, db


def _make_dossier(client, app, name="Target"):
    from models import Dossier

    client.post("/dossier/new", data={"name": name, "authorized": "yes"})
    with app.app_context():
        return db.session.query(Dossier).filter_by(name=name).one().id


def test_reclaim_orphaned_running_jobs(client, app):
    register(client)
    dossier_id = _make_dossier(client, app)
    with app.app_context():
        user = db.session.query(User).one()
        job = ScanJob(
            dossier_id=dossier_id,
            user_id=user.id,
            module="breach",
            params="orphan@example.com",
            status=ScanJob.STATUS_RUNNING,
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

        assert reclaim_orphaned_scan_jobs() == 1
        job = db.session.get(ScanJob, job_id)
        assert job.status == ScanJob.STATUS_QUEUED
        assert job.started_at is None
        assert "Requeued" in job.message


def test_claim_and_process_queued_job_without_eager(tmp_path):
    """Jobs stay queued until the durable worker claims them."""
    from app import create_app

    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(tmp_path / "worker.db"),
            "DOSSIER_DATA_DIR": str(tmp_path / "data"),
            "SCAN_JOBS_EAGER": False,
            "SCAN_WORKER_ENABLED": False,
        }
    )
    os.makedirs(application.config["DOSSIER_DATA_DIR"], exist_ok=True)
    client = application.test_client()
    register(client)
    dossier_id = _make_dossier(client, application)

    client.post(
        f"/dossier/{dossier_id}/osint/breach",
        data={"email": "demo@example.com"},
    )
    with application.app_context():
        job = db.session.query(ScanJob).one()
        assert job.status == ScanJob.STATUS_QUEUED
        assert job.finished_at is None

    processed = process_one_queued_scan(application)
    assert processed is not None

    with application.app_context():
        job = db.session.query(ScanJob).one()
        assert job.status == ScanJob.STATUS_SUCCESS
        assert job.finished_at is not None
        assert claim_next_scan_job() is None
