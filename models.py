"""Database models for DossierForge.

Uses SQLAlchemy so the storage backend can move from SQLite (dev) to
Postgres (production) without code changes. Dossier metadata, ownership,
authorization attestations, and the audit trail live here; large recon
artifacts (WHOIS text, nmap XML, OSINT JSON) remain on disk under a
per-dossier data directory.
"""

from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


def _utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    dossiers = db.relationship(
        "Dossier", back_populates="owner", cascade="all, delete-orphan"
    )
    audit_logs = db.relationship(
        "AuditLog", back_populates="user", cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Dossier(db.Model):
    __tablename__ = "dossiers"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    name = db.Column(db.String(255), nullable=False)
    alias = db.Column(db.String(255), default="")
    organization = db.Column(db.String(255), default="")
    # Authorized-use attestation: recon may only be run against targets the
    # user is authorized to investigate. We record that they attested this.
    authorization_scope = db.Column(db.Text, default="")
    attested_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    owner = db.relationship("User", back_populates="dossiers")
    audit_logs = db.relationship(
        "AuditLog",
        back_populates="dossier",
        cascade="all, delete-orphan",
        order_by="AuditLog.created_at.desc()",
    )


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    dossier_id = db.Column(
        db.Integer, db.ForeignKey("dossiers.id"), nullable=True, index=True
    )
    action = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.String(512), default="")
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    user = db.relationship("User", back_populates="audit_logs")
    dossier = db.relationship("Dossier", back_populates="audit_logs")
