import os
import json

def save_reports(target_domain, report_data, output_base="reports"):
    """Generates structured JSON, summary text, and Markdown reports."""
    target_dir = os.path.join(output_base, target_domain)
    os.makedirs(target_dir, exist_ok=True)

    # 1. JSON Report
    json_path = os.path.join(target_dir, "recon_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

    # 2. Text Summary
    summary_path = os.path.join(target_dir, "summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(f"Target Domain: {target_domain}\n")
        f.write(f"Timestamp: {report_data.get('timestamp')}\n\n")

        ip_info = report_data.get("dns", {})
        f.write("[Stage 1: DNS Resolution]\n")
        f.write(f"Primary IP: {ip_info.get('primary_ip', 'N/A')}\n")
        f.write(f"All IPs: {', '.join(ip_info.get('all_ips', []))}\n")
        f.write(f"Reverse Host: {ip_info.get('reverse_hostname', 'N/A')}\n\n")

        dns_rec = report_data.get("dns_records", {})
        if dns_rec.get("status") == "success":
            email_sec = dns_rec.get("email_security", {})
            f.write("[Stage 2: Email Security & DNS Records]\n")
            f.write(f"MX Servers: {', '.join(email_sec.get('mx_servers', []))}\n")
            f.write(f"SPF Configured: {email_sec.get('spf', {}).get('configured')} - {email_sec.get('spf', {}).get('risk')}\n")
            f.write(f"DMARC Configured: {email_sec.get('dmarc', {}).get('configured')} - {email_sec.get('dmarc', {}).get('risk')}\n\n")

        ssl_info = report_data.get("ssl", {})
        if ssl_info.get("status") == "success":
            f.write("[Stage 3: SSL/TLS Certificate]\n")
            f.write(f"TLS Version: {ssl_info.get('tls_version')}\n")
            f.write(f"Cipher: {ssl_info.get('cipher_suite')}\n")
            f.write(f"Days Until Expiration: {ssl_info.get('days_remaining')}\n\n")

        hdr_info = report_data.get("headers", {})
        if hdr_info.get("status") == "success":
            f.write("[Stage 4: HTTP Security Headers]\n")
            f.write(f"Final URL: {hdr_info.get('final_url')}\n")
            f.write(f"Status Code: {hdr_info.get('status_code')}\n")
            f.write(f"Security Score: {hdr_info.get('security_score')}\n")
            f.write(f"Missing Headers: {', '.join(hdr_info.get('security_headers_missing', []))}\n\n")

        tech_info = report_data.get("technologies", {})
        if tech_info.get("status") == "success":
            f.write("[Stage 5: Web Technologies]\n")
            f.write(f"Server: {tech_info.get('server')}\n")
            f.write(f"CMS: {tech_info.get('detected_cms')}\n")
            f.write(f"Technologies: {', '.join(tech_info.get('technologies', []))}\n\n")

        end_info = report_data.get("endpoints", {})
        if end_info.get("status") == "success":
            f.write("[Stage 6: Sensitive Endpoints]\n")
            f.write(f"Accessible Endpoints: {len(end_info.get('accessible_endpoints', []))}\n")
            for item in end_info.get("accessible_endpoints", []):
                f.write(f"  - {item['path']} ({item['name']})\n")
            f.write("\n")

        port_info = report_data.get("ports", {})
        if port_info.get("status") == "success":
            f.write("[Stage 7: Port Reachability]\n")
            f.write(f"Open Ports ({port_info.get('open_count')}/{port_info.get('scanned_count')}):\n")
            for item in port_info.get("open_ports", []):
                f.write(f"  - Port {item['port']} ({item['service']}): OPEN\n")
            f.write("\n")

        subs_info = report_data.get("subdomains", {})
        if subs_info.get("status") == "success":
            f.write(f"[Stage 8: Subdomains Found: {subs_info.get('count')}]\n")
            for sub in subs_info.get("subdomains", [])[:50]:
                f.write(f"  - {sub}\n")
            f.write("\n")

        intel_info = report_data.get("threat_intel", {})
        if intel_info.get("status") == "success":
            f.write("[Stage 9: WHOIS & Network Intel]\n")
            f.write(f"ASN: {intel_info.get('asn')}\n")
            f.write(f"Org: {intel_info.get('org')}\n")
            f.write(f"Location: {intel_info.get('city')}, {intel_info.get('country')}\n")
            f.write(f"Registrar: {intel_info.get('registrar')}\n\n")

        url_info = report_data.get("urls_discovery", {})
        if url_info.get("status") == "success":
            f.write(f"[Stage 10: URLs & Parameters - Discovered: {url_info.get('total_urls', 0)}]\n")
            f.write(f"Parameterized URLs: {url_info.get('total_parameterized', 0)}\n")
            f.write(f"Unique Parameters: {', '.join(url_info.get('unique_parameters', []))}\n\n")

        vuln_info = report_data.get("vuln_urls", {})
        if vuln_info.get("status") == "success":
            f.write("[Stage 11: Vulnerability Vector URLs]\n")
            f.write(f"XSS Payload URLs: {vuln_info.get('xss_count')}\n")
            f.write(f"SQLi Payload URLs: {vuln_info.get('sqli_count')}\n")
            f.write(f"IDOR Test Vectors: {vuln_info.get('idor_count')}\n\n")

    # Dedicated URL & Payload output files
    url_info = report_data.get("urls_discovery", {})
    if url_info.get("status") == "success":
        urls_txt_path = os.path.join(target_dir, "urls.txt")
        with open(urls_txt_path, "w", encoding="utf-8") as uf:
            for u in url_info.get("urls", []):
                uf.write(f"{u}\n")

        param_urls_txt_path = os.path.join(target_dir, "urls_with_params.txt")
        with open(param_urls_txt_path, "w", encoding="utf-8") as pf:
            for pu in url_info.get("parameterized_urls", []):
                pf.write(f"{pu}\n")

    vuln_info = report_data.get("vuln_urls", {})
    if vuln_info.get("status") == "success":
        xss_path = os.path.join(target_dir, "xss_urls.txt")
        with open(xss_path, "w", encoding="utf-8") as xf:
            for xu in vuln_info.get("xss_urls", []):
                xf.write(f"{xu}\n")

        sqli_path = os.path.join(target_dir, "sqli_urls.txt")
        with open(sqli_path, "w", encoding="utf-8") as sf:
            for su in vuln_info.get("sqli_urls", []):
                sf.write(f"{su}\n")

        idor_path = os.path.join(target_dir, "idor_urls.txt")
        with open(idor_path, "w", encoding="utf-8") as idf:
            for iu in vuln_info.get("idor_urls", []):
                idf.write(f"{iu}\n")

    # 3. Markdown Report
    md_path = os.path.join(target_dir, "report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Security Reconnaissance Report: `{target_domain}`\n\n")
        f.write(f"- **Generated**: {report_data.get('timestamp')}\n")
        f.write(f"- **Primary IP**: `{report_data.get('dns', {}).get('primary_ip', 'N/A')}`\n\n")

        f.write("## 1. DNS & IP Resolution\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('dns', {}), indent=2)}\n```\n\n")

        f.write("## 2. DNS Records & Email Security (SPF / DMARC)\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('dns_records', {}), indent=2)}\n```\n\n")

        f.write("## 3. SSL/TLS Certificate Audit\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('ssl', {}), indent=2)}\n```\n\n")

        f.write("## 4. HTTP Security Headers\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('headers', {}), indent=2)}\n```\n\n")

        f.write("## 5. Technology Stack & Framework Fingerprinting\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('technologies', {}), indent=2)}\n```\n\n")

        f.write("## 6. Sensitive Endpoints & File Disclosure\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('endpoints', {}), indent=2)}\n```\n\n")

        f.write("## 7. Port Reachability\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('ports', {}), indent=2)}\n```\n\n")

        f.write("## 8. Passive Subdomain Discovery\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('subdomains', {}), indent=2)}\n```\n\n")

        f.write("## 9. WHOIS, ASN & Network Intelligence\n\n")
        f.write(f"```json\n{json.dumps(report_data.get('threat_intel', {}), indent=2)}\n```\n\n")

        f.write("## 10. Discovered URLs & Parameters\n\n")
        url_summary = {
            "total_urls": url_info.get("total_urls", 0),
            "total_parameterized": url_info.get("total_parameterized", 0),
            "unique_parameters": url_info.get("unique_parameters", []),
            "sample_urls": url_info.get("sample_urls", []),
            "sample_parameterized_urls": url_info.get("sample_parameterized_urls", [])
        }
        f.write(f"```json\n{json.dumps(url_summary, indent=2)}\n```\n\n")

        f.write("## 11. Vulnerability Payload Vectors (XSS, SQLi, IDOR)\n\n")
        vuln_summary = {
            "xss_count": vuln_info.get("xss_count", 0),
            "sqli_count": vuln_info.get("sqli_count", 0),
            "idor_count": vuln_info.get("idor_count", 0),
            "sample_xss": vuln_info.get("xss_urls", [])[:5],
            "sample_sqli": vuln_info.get("sqli_urls", [])[:5],
            "sample_idor": vuln_info.get("idor_urls", [])[:5]
        }
        f.write(f"```json\n{json.dumps(vuln_summary, indent=2)}\n```\n")

    return target_dir
