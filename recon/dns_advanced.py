import requests

def _query_doh(domain, record_type, timeout=5.0):
    """Queries DNS-over-HTTPS (DoH) via Cloudflare DNS resolver."""
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"
    headers = {"Accept": "application/dns-json"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            return [a.get("data", "").strip('"') for a in answers if "data" in a]
    except Exception:
        pass
    return []

def audit_dns_and_email_security(domain, timeout=5.0):
    """Audits DNS records (MX, TXT, NS, SOA, AAAA) and email security (SPF, DMARC)."""
    results = {
        "domain": domain,
        "records": {},
        "email_security": {
            "spf": {"configured": False, "policy": None, "risk": "High - No SPF found"},
            "dmarc": {"configured": False, "policy": None, "risk": "High - No DMARC found"},
            "mx_servers": []
        }
    }

    # 1. Fetch MX Records
    mx_records = _query_doh(domain, "MX", timeout)
    results["records"]["MX"] = mx_records
    results["email_security"]["mx_servers"] = mx_records

    # 2. Fetch TXT Records
    txt_records = _query_doh(domain, "TXT", timeout)
    results["records"]["TXT"] = txt_records

    # 3. Check SPF
    for txt in txt_records:
        if txt.startswith("v=spf1"):
            results["email_security"]["spf"]["configured"] = True
            results["email_security"]["spf"]["policy"] = txt
            if "+all" in txt:
                results["email_security"]["spf"]["risk"] = "Critical (+all permits any host to spoof domain)"
            elif "?all" in txt:
                results["email_security"]["spf"]["risk"] = "Medium (Neutral ?all provides no spoof enforcement)"
            elif "~all" in txt:
                results["email_security"]["spf"]["risk"] = "Low (SoftFail ~all)"
            elif "-all" in txt:
                results["email_security"]["spf"]["risk"] = "Strict Pass/Secure (-all enforces hard fail)"
            break

    # 4. Check DMARC (_dmarc.<domain>)
    dmarc_records = _query_doh(f"_dmarc.{domain}", "TXT", timeout)
    results["records"]["DMARC"] = dmarc_records
    for d in dmarc_records:
        if d.startswith("v=DMARC1"):
            results["email_security"]["dmarc"]["configured"] = True
            results["email_security"]["dmarc"]["policy"] = d
            if "p=reject" in d:
                results["email_security"]["dmarc"]["risk"] = "Strict & Secure (p=reject)"
            elif "p=quarantine" in d:
                results["email_security"]["dmarc"]["risk"] = "Moderate (p=quarantine)"
            elif "p=none" in d:
                results["email_security"]["dmarc"]["risk"] = "Warning (p=none - monitoring mode only, no spoof prevention)"
            break

    # 5. Fetch NS & SOA Records
    results["records"]["NS"] = _query_doh(domain, "NS", timeout)
    results["records"]["SOA"] = _query_doh(domain, "SOA", timeout)
    results["records"]["AAAA"] = _query_doh(domain, "AAAA", timeout)

    return {
        "status": "success",
        **results
    }
