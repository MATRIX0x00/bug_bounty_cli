import requests

def gather_network_intel(domain, ip=None, timeout=6.0):
    """Fetches ASN, IP Geolocation, and RDAP registration details."""
    intel = {
        "asn": "N/A",
        "org": "N/A",
        "isp": "N/A",
        "country": "N/A",
        "city": "N/A",
        "rdap_domain": domain,
        "registrar": "N/A"
    }

    # 1. IP Geolocation & ASN via ip-api
    if ip:
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                intel["asn"] = data.get("as", "N/A")
                intel["org"] = data.get("org", "N/A")
                intel["isp"] = data.get("isp", "N/A")
                intel["country"] = data.get("country", "N/A")
                intel["city"] = data.get("city", "N/A")
        except Exception:
            pass

    # 2. Domain RDAP
    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(rdap_url, timeout=timeout, headers={"User-Agent": "Recon-CLI/2.0"})
        if resp.status_code == 200:
            rdap_data = resp.json()
            for entity in rdap_data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                intel["registrar"] = item[3]
                                break
    except Exception:
        pass

    return {
        "status": "success",
        **intel
    }
