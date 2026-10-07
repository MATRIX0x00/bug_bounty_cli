import requests

TECH_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "CloudFront / AWS": ["cloudfront", "x-amz-cf-id", "x-amz-id-2"],
    "Fastly": ["fastly", "x-fastly-request-id"],
    "Akamai": ["akamai", "x-akamai-transformed"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "Microsoft-IIS": ["iis", "microsoft-iis"],
    "LiteSpeed": ["litespeed"],
    "Envoy": ["envoy"],
    "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
    "Joomla": ["joomla!", "/templates/"],
    "Drupal": ["drupal", "sites/default/files"],
    "Shopify": ["cdn.shopify.com", "myshopify"],
    "Next.js": ["__next", "_next/static"],
    "React": ["react.development.js", "react.production.min.js", "data-reactroot"],
    "Vue.js": ["vue.js", "data-v-"],
    "PHP": ["phpsessid", "x-powered-by: php"],
    "ASP.NET": ["asp.net", "aspnet", "x-aspnet-version"],
    "Express.js": ["express"],
    "Tailwind CSS": ["tailwind"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.css"]
}

def fingerprint_technology(domain, timeout=6.0):
    """Fingerprints web servers, CMS, backend runtimes, and frameworks."""
    url = f"https://{domain}"
    detected = set()
    headers_matched = {}
    cms_detected = None
    server_name = "Unknown"

    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, allow_redirects=True)
    except requests.RequestException:
        url = f"http://{domain}"
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, allow_redirects=True)
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    server_name = resp.headers.get("Server", "Hidden / Not provided")
    powered_by = resp.headers.get("X-Powered-By", "Hidden / Not provided")
    cookies = " ".join(resp.cookies.keys()).lower()
    html_snippet = resp.text[:15000].lower() if resp.text else ""
    headers_str = " ".join([f"{k}:{v}" for k, v in resp.headers.items()]).lower()

    # Match signatures
    for tech, indicators in TECH_SIGNATURES.items():
        for ind in indicators:
            ind_l = ind.lower()
            if ind_l in headers_str or ind_l in cookies or ind_l in html_snippet:
                detected.add(tech)
                if tech in ["WordPress", "Joomla", "Drupal", "Shopify"]:
                    cms_detected = tech
                break

    return {
        "status": "success",
        "server": server_name,
        "x_powered_by": powered_by,
        "detected_cms": cms_detected or "None / Custom application",
        "technologies": sorted(list(detected)),
        "cookie_names": list(resp.cookies.keys())
    }
