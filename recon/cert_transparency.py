import requests

def _fetch_from_crtsh(domain, timeout):
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    if resp.status_code == 200:
        data = resp.json()
        for entry in data:
            name_val = entry.get("name_value", "")
            for item in name_val.split("\n"):
                clean = item.strip().lower()
                if clean and not clean.startswith("*") and domain in clean:
                    subdomains.add(clean)
    return subdomains

def _fetch_from_alienvault(domain, timeout):
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Recon-CLI/2.0"})
    if resp.status_code == 200:
        data = resp.json()
        records = data.get("passive_dns", [])
        for item in records:
            hostname = item.get("hostname", "").strip().lower()
            if hostname and domain in hostname:
                subdomains.add(hostname)
    return subdomains

def _fetch_from_hackertarget(domain, timeout):
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Recon-CLI/2.0"})
    if resp.status_code == 200 and not resp.text.startswith("error") and not resp.text.startswith("API count exceeded"):
        lines = resp.text.strip().split("\n")
        for line in lines:
            parts = line.split(",")
            if parts:
                h = parts[0].strip().lower()
                if h and domain in h:
                    subdomains.add(h)
    return subdomains

def query_subdomains_crtsh(domain, timeout=8.0):
    """Discovers subdomains passively with fallback redundancy against crt.sh timeouts."""
    all_subs = set()
    sources_succeeded = []
    errors = []

    # Source 1: crt.sh
    try:
        crt_subs = _fetch_from_crtsh(domain, timeout)
        if crt_subs:
            all_subs.update(crt_subs)
            sources_succeeded.append("crt.sh")
    except Exception as e:
        errors.append(f"crt.sh notice: {str(e)}")

    # Source 2: AlienVault OTX
    try:
        av_subs = _fetch_from_alienvault(domain, timeout)
        if av_subs:
            all_subs.update(av_subs)
            sources_succeeded.append("AlienVault OTX")
    except Exception as e:
        errors.append(f"AlienVault notice: {str(e)}")

    # Source 3: HackerTarget (passive hostsearch)
    try:
        ht_subs = _fetch_from_hackertarget(domain, timeout)
        if ht_subs:
            all_subs.update(ht_subs)
            sources_succeeded.append("HackerTarget")
    except Exception as e:
        errors.append(f"HackerTarget notice: {str(e)}")

    sorted_subs = sorted(list(all_subs))
    if sorted_subs:
        return {
            "status": "success",
            "count": len(sorted_subs),
            "subdomains": sorted_subs,
            "active_sources": sources_succeeded
        }
    
    if errors:
        return {
            "status": "error",
            "message": "; ".join(errors),
            "subdomains": []
        }

    return {
        "status": "success",
        "count": 0,
        "subdomains": [],
        "active_sources": sources_succeeded
    }
