"""Dossier export/reporting.

Renders an assembled dossier report dict (built in the app from the database
plus on-disk recon artifacts) into shareable formats. Pure functions with no
Flask or DB dependency, so they are easy to unit test.
"""

import json


def render_json(report):
    return json.dumps(report, indent=2, default=str)


def _fmt(value):
    return value if value not in (None, "", []) else "N/A"


def render_markdown(report):
    """Render a report dict into a Markdown dossier report."""
    lines = []
    lines.append(f"# Dossier Report: {report.get('name', 'Unknown')}")
    lines.append("")
    lines.append(f"- **Generated:** {report.get('generated_at', 'N/A')}")
    lines.append(f"- **Alias:** {_fmt(report.get('alias'))}")
    lines.append(f"- **Organization:** {_fmt(report.get('organization'))}")
    lines.append(f"- **Created:** {_fmt(report.get('created_at'))}")
    lines.append("")

    tags = report.get("tags") or []
    if tags:
        lines.append(f"- **Tags:** {', '.join(tags)}")
        lines.append("")

    lines.append("## Authorized use")
    lines.append(f"- **Attested at:** {_fmt(report.get('attested_at'))}")
    lines.append(f"- **Scope / reference:** {_fmt(report.get('authorization_scope'))}")
    lines.append("")

    notes = report.get("notes") or []
    if notes:
        lines.append("## Notes")
        for n in notes:
            lines.append(f"- _{n.get('at')} — {n.get('author')}_")
            lines.append(f"  {n.get('body')}")
        lines.append("")

    assets = report.get("assets") or {}
    lines.append("## Discovered assets")
    lines.append(f"- **Domains:** {', '.join(assets.get('domains', [])) or 'None'}")
    lines.append(
        f"- **IP addresses:** {', '.join(assets.get('ip_addresses', [])) or 'None'}"
    )
    lines.append(f"- **Emails:** {', '.join(assets.get('emails', [])) or 'None'}")
    lines.append(
        f"- **Social media:** {', '.join(assets.get('social_media', [])) or 'None'}"
    )
    lines.append("")

    whois = report.get("whois")
    if whois:
        lines.append("## WHOIS")
        lines.append(f"- **Domain:** {_fmt(whois.get('domain'))}")
        lines.append(f"- **Registrar:** {_fmt(whois.get('registrar'))}")
        lines.append(f"- **Creation date:** {_fmt(whois.get('creation_date'))}")
        lines.append(f"- **Expiration date:** {_fmt(whois.get('expiration_date'))}")
        lines.append(
            f"- **Name servers:** {', '.join(whois.get('name_servers', [])) or 'N/A'}"
        )
        lines.append("")

    open_ports = report.get("open_ports") or []
    if open_ports:
        lines.append("## Open ports")
        lines.append("")
        lines.append("| Port | Protocol | Service | Product | Version |")
        lines.append("|---|---|---|---|---|")
        for p in open_ports:
            lines.append(
                f"| {p.get('port')} | {p.get('protocol')} | "
                f"{p.get('service') or 'unknown'} | {p.get('product') or 'N/A'} | "
                f"{p.get('version') or 'N/A'} |"
            )
        lines.append("")

    osint = report.get("osint") or {}
    breaches = osint.get("breaches") or []
    if breaches:
        lines.append("## Breach checks")
        for b in breaches:
            count = len(b.get("breaches", []))
            status = f"found in {count} breach(es)" if count else "no breaches found"
            lines.append(f"- **{b.get('email')}**: {status}")
        lines.append("")

    github_profiles = osint.get("github_profiles") or []
    if github_profiles:
        lines.append("## GitHub profiles")
        for g in github_profiles:
            profile = g.get("profile") or {}
            lines.append(
                f"- **{g.get('username')}**: {_fmt(profile.get('name'))} "
                f"({_fmt(profile.get('public_repos'))} public repos)"
            )
        lines.append("")

    audit = report.get("audit") or []
    if audit:
        lines.append("## Audit trail")
        lines.append("")
        lines.append("| Timestamp | Action | Detail |")
        lines.append("|---|---|---|")
        for a in audit:
            lines.append(
                f"| {a.get('at')} | {a.get('action')} | {a.get('detail') or ''} |"
            )
        lines.append("")

    return "\n".join(lines)
