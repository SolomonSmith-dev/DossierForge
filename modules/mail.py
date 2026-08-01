"""Outbound email helpers for DossierForge.

Backends (config ``MAIL_BACKEND``):
- ``console`` (default) — log the message; good for local/dev with no SMTP
- ``memory`` — append to an in-process outbox (tests)
- ``smtp`` — send via ``MAIL_SERVER`` / ``MAIL_PORT`` / credentials

No third-party mail library required; SMTP uses the stdlib.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from flask import current_app

logger = logging.getLogger(__name__)

# In-process outbox used when MAIL_BACKEND=memory (cleared between tests).
_outbox: list[dict] = []


def clear_outbox():
    _outbox.clear()


def get_outbox():
    return list(_outbox)


def send_email(*, to, subject, text_body, html_body=None):
    """Send one email. Returns True on success, False on failure."""
    to = (to or "").strip().lower()
    if not to:
        return False

    sender = current_app.config.get("MAIL_FROM") or "noreply@dossierforge.local"
    backend = (current_app.config.get("MAIL_BACKEND") or "console").lower()
    payload = {
        "to": to,
        "from": sender,
        "subject": subject,
        "text": text_body,
        "html": html_body or "",
    }

    if backend == "memory":
        _outbox.append(payload)
        return True

    if backend == "smtp":
        return _send_smtp(payload)

    # console / unknown → log (never raise)
    logger.info(
        "MAIL console → to=%s subject=%r\n%s",
        to,
        subject,
        text_body,
    )
    print(f"[mail:{backend}] to={to} subject={subject}\n{text_body}\n")
    return True


def _send_smtp(payload):
    server = current_app.config.get("MAIL_SERVER") or ""
    if not server:
        logger.error("MAIL_BACKEND=smtp but MAIL_SERVER is empty")
        return False
    port = int(current_app.config.get("MAIL_PORT") or 587)
    use_tls = bool(current_app.config.get("MAIL_USE_TLS", True))
    username = current_app.config.get("MAIL_USERNAME") or ""
    password = current_app.config.get("MAIL_PASSWORD") or ""

    msg = EmailMessage()
    msg["Subject"] = payload["subject"]
    msg["From"] = payload["from"]
    msg["To"] = payload["to"]
    msg.set_content(payload["text"])
    if payload.get("html"):
        msg.add_alternative(payload["html"], subtype="html")

    try:
        with smtplib.SMTP(server, port, timeout=30) as smtp:
            if use_tls:
                smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 - surface as soft failure
        logger.exception("SMTP send failed: %s", exc)
        return False


def send_invitation_email(invite, accept_url, invited_by_email=None):
    """Compose and send an invitation email for a pending Invitation."""
    if invite.kind == "org":
        target = (
            invite.organization.name
            if getattr(invite, "organization", None)
            else "an organization"
        )
        what_plain = f"join {target} as {invite.role}"
        what_html = f"join <strong>{target}</strong> as {invite.role}"
    else:
        target = (
            invite.dossier.name if getattr(invite, "dossier", None) else "a dossier"
        )
        what_plain = f"collaborate on dossier {target} as {invite.role}"
        what_html = f"collaborate on dossier <strong>{target}</strong> as {invite.role}"

    inviter = invited_by_email or "A DossierForge user"
    subject = f"You're invited to DossierForge ({invite.kind})"
    text = (
        f"{inviter} invited you to {what_plain} on DossierForge.\n\n"
        f"Accept this invitation:\n{accept_url}\n\n"
        f"Sign up or log in with {invite.email} to claim access.\n"
        f"If you did not expect this, you can ignore this email.\n"
    )
    html = (
        f"<p>{inviter} invited you to {what_html} on DossierForge.</p>"
        f'<p><a href="{accept_url}">Accept invitation</a></p>'
        f"<p>Sign up or log in with <strong>{invite.email}</strong> "
        f"to claim access.</p>"
        f"<p style='color:#666'>If you did not expect this, you can ignore "
        f"this email.</p>"
    )
    return send_email(to=invite.email, subject=subject, text_body=text, html_body=html)
