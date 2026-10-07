import requests
from urllib.parse import urlparse, parse_qs

def _fetch_wayback_urls(domain, timeout=10.0, limit=2000):
    urls = set()
    endpoint = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    try:
        resp = requests.get(endpoint, timeout=timeout, headers={"User-Agent": "Recon-CLI/2.0"})
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                for entry in data[1:]:
                    if entry and isinstance(entry, list) and len(entry) > 0:
                        urls.add(entry[0].strip())
    except Exception:
        pass
    return urls

def _fetch_alienvault_urls(domain, timeout=10.0):
    urls = set()
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
    try:
        resp = requests.get(endpoint, timeout=timeout, headers={"User-Agent": "Recon-CLI/2.0"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("url_list", []):
                raw_url = item.get("url", "").strip()
                if raw_url:
                    urls.add(raw_url)
    except Exception:
        pass
    return urls

def gather_domain_urls(domain, timeout=10.0):
    """Passively discovers archived URLs and extracts endpoints and query parameters."""
    all_urls = set()
    sources = []

    # 1. Wayback Machine CDX API
    wb_urls = _fetch_wayback_urls(domain, timeout=timeout)
    if wb_urls:
        all_urls.update(wb_urls)
        sources.append("Wayback Machine")

    # 2. AlienVault OTX URL List
    av_urls = _fetch_alienvault_urls(domain, timeout=timeout)
    if av_urls:
        all_urls.update(av_urls)
        sources.append("AlienVault OTX")

    sorted_urls = sorted(list(all_urls))
    param_urls = []
    discovered_params = set()

    for u in sorted_urls:
        parsed = urlparse(u)
        if parsed.query:
            param_urls.append(u)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for p in params.keys():
                discovered_params.add(p)

    return {
        "status": "success",
        "active_sources": sources,
        "total_urls": len(sorted_urls),
        "total_parameterized": len(param_urls),
        "unique_params_count": len(discovered_params),
        "unique_parameters": sorted(list(discovered_params)),
        "urls": sorted_urls,
        "parameterized_urls": param_urls,
        "sample_urls": sorted_urls[:10],
        "sample_parameterized_urls": param_urls[:10]
    }
