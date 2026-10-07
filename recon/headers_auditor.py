import requests

CRITICAL_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy"
]

def audit_security_headers(domain, timeout=8.0):
    """Evaluates HTTP/HTTPS security posture based on response headers."""
    url = f"https://{domain}"
    response = None
    used_protocol = "https"

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "Recon-CLI/2.0"})
    except requests.RequestException:
        url = f"http://{domain}"
        used_protocol = "http"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "Recon-CLI/2.0"})
        except requests.RequestException as e:
            return {
                "status": "error",
                "message": str(e)
            }

    present_headers = {}
    missing_headers = []

    for header in CRITICAL_SECURITY_HEADERS:
        val = response.headers.get(header)
        if val:
            present_headers[header] = val
        else:
            missing_headers.append(header)

    score = round((len(present_headers) / len(CRITICAL_SECURITY_HEADERS)) * 100, 1)

    return {
        "status": "success",
        "initial_protocol": used_protocol,
        "final_url": response.url,
        "status_code": response.status_code,
        "server": response.headers.get("Server", "Hidden / Not provided"),
        "content_type": response.headers.get("Content-Type", "N/A"),
        "security_score": f"{score}%",
        "security_headers_present": present_headers,
        "security_headers_missing": missing_headers
    }
