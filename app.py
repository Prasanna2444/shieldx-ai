from urllib.parse import urlparse
import ipaddress
import re


def scan_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        return {"valid": False, "error": "Please enter a URL."}

    if any(c.isspace() or ord(c) < 32 for c in raw_url):
        return {
            "valid": False,
            "error": "The URL contains spaces or invalid characters."
        }

    try:
        parsed = urlparse(raw_url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError

        host = parsed.hostname
        if not host or "." not in host:
            raise ValueError

        _ = parsed.port
        host = host.rstrip(".").lower()

    except ValueError:
        return {
            "valid": False,
            "error": "Enter a valid URL starting with http:// or https://."
        }

    score = 0
    findings = []

    def flag(points, message):
        nonlocal score
        score += points
        findings.append(message)

    try:
        ipaddress.ip_address(host)
        flag(25, "The hostname is an IP address.")
    except ValueError:
        pass

    if "@" in parsed.netloc:
        flag(25, "The URL contains an @ symbol in its authority.")

    if len(raw_url) > 100:
        flag(10, "The URL is unusually long.")

    if host.count("-") >= 3:
        flag(10, "The hostname contains several hyphens.")

    if re.search(
        r"login|verify|account|password|signin",
        parsed.path + "?" + parsed.query,
        re.IGNORECASE
    ):
        flag(10, "The URL contains account-related terms.")

    if parsed.scheme.lower() == "http":
        flag(5, "The URL does not use HTTPS.")

    score = min(score, 100)

    if score >= 40:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return {
        "valid": True,
        "host": host,
        "score": score,
        "level": level,
        "findings": findings
    } 
