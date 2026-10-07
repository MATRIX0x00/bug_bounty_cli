import requests

COMMON_ENDPOINTS = [
    ("/robots.txt", "Robots Exclusion Protocol"),
    ("/sitemap.xml", "XML Sitemap"),
    ("/.well-known/security.txt", "Security Vulnerability Disclosure File"),
    ("/.well-known/openid-configuration", "OpenID Connect Configuration"),
    ("/.git/HEAD", "Exposed Git Repository Header"),
    ("/.env", "Exposed Environment Variables File"),
    ("/.DS_Store", "Exposed macOS Directory Store")
]

def audit_sensitive_endpoints(domain, timeout=5.0):
    """Audits presence of standard security and exposed administrative endpoints."""
    base_url = f"https://{domain}"
    results = {}
    findings = []
    robots_disallowed_paths = []

    for path, description in COMMON_ENDPOINTS:
        target = f"{base_url}{path}"
        try:
            resp = requests.get(
                target,
                timeout=timeout,
                headers={"User-Agent": "Recon-CLI/2.0"},
                allow_redirects=False
            )
            status = resp.status_code
            is_present = (status == 200)

            # Validate true Git presence vs generic 200 HTML
            if path == "/.git/HEAD" and is_present:
                if "ref: refs/" not in resp.text:
                    is_present = False

            # Validate true .env
            if path == "/.env" and is_present:
                if "=" not in resp.text or "<html" in resp.text.lower():
                    is_present = False

            results[path] = {
                "description": description,
                "status_code": status,
                "accessible": is_present
            }

            if is_present:
                findings.append({"path": path, "name": description, "code": status})

            # Parse robots.txt disallowed rules
            if path == "/robots.txt" and is_present and resp.text:
                for line in resp.text.splitlines():
                    line_str = line.strip()
                    if line_str.lower().startswith("disallow:"):
                        rule = line_str.split(":", 1)[1].strip()
                        if rule and rule not in robots_disallowed_paths:
                            robots_disallowed_paths.append(rule)
        except Exception:
            results[path] = {
                "description": description,
                "status_code": None,
                "accessible": False
            }

    return {
        "status": "success",
        "endpoints_checked": len(COMMON_ENDPOINTS),
        "accessible_endpoints": findings,
        "robots_disallowed_entries": robots_disallowed_paths[:10],
        "details": results
    }
