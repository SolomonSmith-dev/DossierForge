import subprocess
import json
import os
from datetime import datetime


def run_whois(domain, dossier_path):
    """
    Run whois query on a domain and save results to dossier.

    Args:
        domain (str): Domain to query (e.g., 'example.com')
        dossier_path (str): Path to dossier directory

    Returns:
        dict: Parsed whois data
    """
    try:
        # Run whois command
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            return {"error": f"WHOIS query failed: {result.stderr}"}

        whois_output = result.stdout

        # Save raw output
        whois_file = os.path.join(dossier_path, "whois.txt")
        with open(whois_file, "w") as f:
            f.write(whois_output)

        # Parse basic info (simple parsing)
        parsed_data = parse_whois_output(whois_output, domain)

        # Save parsed data
        parsed_file = os.path.join(dossier_path, "whois_parsed.json")
        with open(parsed_file, "w") as f:
            json.dump(parsed_data, f, indent=2)

        return parsed_data

    except subprocess.TimeoutExpired:
        return {"error": "WHOIS query timed out"}
    except Exception as e:
        return {"error": f"WHOIS query failed: {str(e)}"}


def parse_whois_output(output, domain):
    """
    Parse WHOIS output to extract key information.

    Args:
        output (str): Raw WHOIS output
        domain (str): Original domain queried

    Returns:
        dict: Parsed WHOIS data
    """
    lines = output.split("\n")
    parsed = {
        "domain": domain,
        "query_time": datetime.now().isoformat(),
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "admin_contact": {},
        "tech_contact": {},
        "registrant": {},
    }

    for line in lines:
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            if key in ["registrar", "sponsoring registrar"]:
                parsed["registrar"] = value
            elif key in ["creation date", "created"]:
                parsed["creation_date"] = value
            elif key in ["expiration date", "expires", "registry expiry date"]:
                parsed["expiration_date"] = value
            elif key in ["updated date", "last updated"]:
                parsed["updated_date"] = value
            elif key in ["name server", "nserver"]:
                if value not in parsed["name_servers"]:
                    parsed["name_servers"].append(value)
            elif key == "status":
                if value not in parsed["status"]:
                    parsed["status"].append(value)

    return parsed


def get_whois_summary(dossier_path):
    """
    Get a summary of WHOIS data for display in the UI.

    Args:
        dossier_path (str): Path to dossier directory

    Returns:
        dict: Summary of WHOIS data
    """
    parsed_file = os.path.join(dossier_path, "whois_parsed.json")
    if not os.path.exists(parsed_file):
        return None

    try:
        with open(parsed_file, "r") as f:
            data = json.load(f)

        return {
            "domain": data.get("domain"),
            "registrar": data.get("registrar"),
            "creation_date": data.get("creation_date"),
            "expiration_date": data.get("expiration_date"),
            "name_servers": data.get("name_servers", [])[:3],  # First 3
            "status": data.get("status", [])[:3],  # First 3
        }
    except Exception:
        return None
