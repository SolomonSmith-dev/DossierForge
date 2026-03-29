import requests
import json
import os
import re
from datetime import datetime


def search_social_media(target, dossier_path):
    """
    Search for social media profiles of a target.

    Args:
        target (str): Name, email, or username to search
        dossier_path (str): Path to dossier directory

    Returns:
        dict: Found social media profiles
    """
    profiles = {
        "target": target,
        "search_time": datetime.now().isoformat(),
        "profiles": {},
        "emails": [],
        "usernames": [],
    }

    # Common social media platforms
    platforms = {
        "github": f"https://github.com/{target}",
        "twitter": f"https://twitter.com/{target}",
        "linkedin": f"https://linkedin.com/in/{target}",
        "instagram": f"https://instagram.com/{target}",
        "facebook": f"https://facebook.com/{target}",
        "youtube": f"https://youtube.com/@{target}",
        "reddit": f"https://reddit.com/user/{target}",
        "medium": f"https://medium.com/@{target}",
        "dev.to": f"https://dev.to/{target}",
        "stackoverflow": f"https://stackoverflow.com/users/{target}",
    }

    for platform, url in platforms.items():
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                profiles["profiles"][platform] = {
                    "url": url,
                    "status": "found",
                    "status_code": response.status_code,
                }
            elif response.status_code == 404:
                profiles["profiles"][platform] = {
                    "url": url,
                    "status": "not_found",
                    "status_code": response.status_code,
                }
            else:
                profiles["profiles"][platform] = {
                    "url": url,
                    "status": "unknown",
                    "status_code": response.status_code,
                }
        except Exception as e:
            profiles["profiles"][platform] = {
                "url": url,
                "status": "error",
                "error": str(e),
            }

    # Save results
    osint_file = os.path.join(dossier_path, "osint_social_media.json")
    with open(osint_file, "w") as f:
        json.dump(profiles, f, indent=2)

    return profiles


def search_emails(domain, dossier_path):
    """
    Search for email addresses associated with a domain.

    Args:
        domain (str): Domain to search for emails
        dossier_path (str): Path to dossier directory

    Returns:
        dict: Found email addresses
    """
    emails = {
        "domain": domain,
        "search_time": datetime.now().isoformat(),
        "emails": [],
        "sources": [],
    }

    # Try to find emails from common sources
    sources = [
        f"https://{domain}/contact",
        f"https://{domain}/about",
        f"https://{domain}/team",
        f"https://{domain}/",
        f"https://www.{domain}/contact",
        f"https://www.{domain}/about",
    ]

    for source in sources:
        try:
            response = requests.get(
                source,
                timeout=10,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
            )
            if response.status_code == 200:
                # Extract emails using regex
                email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                found_emails = re.findall(email_pattern, response.text)

                for email in found_emails:
                    if domain in email.lower() and email not in emails["emails"]:
                        emails["emails"].append(email)
                        emails["sources"].append({"email": email, "source": source})
        except Exception:
            continue

    # Save results
    email_file = os.path.join(dossier_path, "osint_emails.json")
    with open(email_file, "w") as f:
        json.dump(emails, f, indent=2)

    return emails


def check_breach_data(email, dossier_path):
    """
    Check if an email appears in known data breaches.
    Note: This is a mock implementation. In production, you'd use APIs like HaveIBeenPwned.

    Args:
        email (str): Email address to check
        dossier_path (str): Path to dossier directory

    Returns:
        dict: Breach data (mock for now)
    """
    breach_data = {
        "email": email,
        "check_time": datetime.now().isoformat(),
        "breaches": [],
        "note": "This is a mock implementation. Use HaveIBeenPwned API for real data.",
    }

    # Mock breach data for demonstration
    mock_breaches = [
        {
            "name": "Example Breach 2023",
            "date": "2023-06-15",
            "description": "Mock breach for demonstration purposes",
            "data_classes": ["email addresses", "passwords"],
            "verified": False,
        }
    ]

    # Randomly assign some mock breaches (for demo purposes)
    import random

    if random.random() < 0.3:  # 30% chance of "finding" a breach
        breach_data["breaches"] = mock_breaches

    # Save results
    breach_file = os.path.join(
        dossier_path, f"osint_breach_{email.replace('@', '_at_')}.json"
    )
    with open(breach_file, "w") as f:
        json.dump(breach_data, f, indent=2)

    return breach_data


def search_github_info(username, dossier_path):
    """
    Search for GitHub information about a username.

    Args:
        username (str): GitHub username to search
        dossier_path (str): Path to dossier directory

    Returns:
        dict: GitHub profile information
    """
    github_data = {
        "username": username,
        "search_time": datetime.now().isoformat(),
        "profile": {},
        "repositories": [],
        "organizations": [],
    }

    try:
        # GitHub API endpoint
        api_url = f"https://api.github.com/users/{username}"
        response = requests.get(api_url, timeout=10)

        if response.status_code == 200:
            profile_data = response.json()
            github_data["profile"] = {
                "name": profile_data.get("name"),
                "bio": profile_data.get("bio"),
                "location": profile_data.get("location"),
                "company": profile_data.get("company"),
                "blog": profile_data.get("blog"),
                "public_repos": profile_data.get("public_repos"),
                "followers": profile_data.get("followers"),
                "following": profile_data.get("following"),
                "created_at": profile_data.get("created_at"),
                "updated_at": profile_data.get("updated_at"),
            }

            # Get repositories
            repos_url = f"https://api.github.com/users/{username}/repos"
            repos_response = requests.get(repos_url, timeout=10)
            if repos_response.status_code == 200:
                repos_data = repos_response.json()
                for repo in repos_data[:10]:  # Limit to 10 most recent
                    github_data["repositories"].append(
                        {
                            "name": repo.get("name"),
                            "description": repo.get("description"),
                            "language": repo.get("language"),
                            "stars": repo.get("stargazers_count"),
                            "forks": repo.get("forks_count"),
                            "url": repo.get("html_url"),
                        }
                    )

    except Exception as e:
        github_data["error"] = str(e)

    # Save results
    github_file = os.path.join(dossier_path, f"osint_github_{username}.json")
    with open(github_file, "w") as f:
        json.dump(github_data, f, indent=2)

    return github_data


def get_osint_summary(dossier_path):
    """
    Get a summary of OSINT data for display in the UI.

    Args:
        dossier_path (str): Path to dossier directory

    Returns:
        dict: Summary of OSINT data
    """
    summary = {"social_media": {}, "emails": [], "breaches": [], "github_profiles": []}

    # Look for OSINT files
    for filename in os.listdir(dossier_path):
        if filename.startswith("osint_"):
            try:
                with open(os.path.join(dossier_path, filename), "r") as f:
                    data = json.load(f)

                if "social_media" in filename:
                    summary["social_media"] = data
                elif "emails" in filename:
                    summary["emails"] = data.get("emails", [])
                elif "breach" in filename:
                    summary["breaches"].append(data)
                elif "github" in filename:
                    summary["github_profiles"].append(data)

            except Exception:
                continue

    return summary
