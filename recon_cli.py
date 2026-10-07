#!/usr/bin/env python3
"""
Advanced Security & Reconnaissance CLI Tool - Multi-Stage Security Auditor
"""
import os
import sys
import argparse
from datetime import datetime, timezone

from recon.display import (
    print_banner,
    log_info,
    log_success,
    log_warn,
    log_error,
    print_section_header,
    display_dns_results,
    display_dns_advanced_results,
    display_ssl_results,
    display_headers_results,
    display_tech_results,
    display_endpoints_results,
    display_ports_results,
    display_subdomains_results,
    display_intel_results,
    display_urls_results,
    display_vuln_urls_results,
    prompt_stage,
    colorize,
    TerminalColors
)
from recon.url_gatherer import gather_domain_urls
from recon.dns_resolver import resolve_domain
from recon.dns_advanced import audit_dns_and_email_security
from recon.ssl_inspector import inspect_ssl
from recon.headers_auditor import audit_security_headers
from recon.tech_stack import fingerprint_technology
from recon.endpoint_auditor import audit_sensitive_endpoints
from recon.port_scanner import scan_ports
from recon.cert_transparency import query_subdomains_crtsh
from recon.threat_intel import gather_network_intel
from recon.vuln_url_generator import generate_vuln_payload_urls
from recon.reporter import save_reports

def clean_target_domain(raw_input):
    clean = raw_input.strip()
    for prefix in ["https://", "http://"]:
        if clean.lower().startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0]
    clean = clean.split(":")[0]
    return clean

def prompt_mode():
    while True:
        print(f"\n{colorize('[?]', TerminalColors.MAGENTA)} Select Operation Mode for Bug Bounty & Recon:")
        print(f"  {colorize('1.', TerminalColors.CYAN)} Reconnaissance Mode (DNS, SSL, Tech Stack, Subdomains, Endpoints, URLs)")
        print(f"  {colorize('2.', TerminalColors.CYAN)} Attacker / Vulnerability Hunting Mode (Bug Bounty Payloads, XSS, SQLi, IDOR Vectors)")
        choice = input(colorize("Enter mode choice (1/2/q): ", TerminalColors.MAGENTA)).strip().lower()
        if choice in ["1", "recon"]:
            return "recon"
        elif choice in ["2", "attacker", "vuln"]:
            return "attacker"
        elif choice in ["q", "quit"]:
            return None
        print("Please enter '1' for Reconnaissance Mode, '2' for Attacker Mode, or 'q' to quit.")

def execute_recon(domain, mode="recon", staged=True, output_dir="reports", timeout=2.0, workers=10):
    print_banner()
    log_info(f"Target domain engaged: {domain}")
    log_info(f"Active Mode Selected: {colorize(mode.upper(), TerminalColors.GREEN)}")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = {
        "target": domain,
        "timestamp": now_iso,
        "mode": mode
    }

    if mode == "recon":
        # Stage 1: DNS & IP Resolution
        proceed = True if not staged else prompt_stage("Stage 1: IP & DNS Resolution")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 1: DNS & IP Resolution")
            dns_res = resolve_domain(domain)
            report["dns"] = dns_res
            display_dns_results(dns_res)
        else:
            report["dns"] = {"status": "skipped"}
            log_info("Stage 1: DNS Resolution skipped.")

        # Stage 2: Advanced DNS Records & Email Security (SPF / DMARC / MX)
        proceed = True if not staged else prompt_stage("Stage 2: Advanced DNS Records & Email Security (SPF/DMARC)")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 2: DNS Records & Email Security Posture")
            dns_adv_res = audit_dns_and_email_security(domain, timeout=timeout * 2.5)
            report["dns_records"] = dns_adv_res
            display_dns_advanced_results(dns_adv_res)
        else:
            report["dns_records"] = {"status": "skipped"}
            log_info("Stage 2: DNS Records & Email Security skipped.")

        # Stage 3: SSL/TLS Verification
        proceed = True if not staged else prompt_stage("Stage 3: SSL/TLS Certificate Analysis")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 3: SSL/TLS Certificate Inspection")
            ssl_res = inspect_ssl(domain, timeout=timeout * 3)
            report["ssl"] = ssl_res
            display_ssl_results(ssl_res)
        else:
            report["ssl"] = {"status": "skipped"}
            log_info("Stage 3: SSL/TLS Analysis skipped.")

        # Stage 4: HTTP Security Headers
        proceed = True if not staged else prompt_stage("Stage 4: HTTP Security Headers Evaluation")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 4: HTTP Security Headers & Posture")
            hdr_res = audit_security_headers(domain, timeout=timeout * 4)
            report["headers"] = hdr_res
            display_headers_results(hdr_res)
        else:
            report["headers"] = {"status": "skipped"}
            log_info("Stage 4: HTTP Security Headers skipped.")

        # Stage 5: Technology Stack & Fingerprinting
        proceed = True if not staged else prompt_stage("Stage 5: Web Technology & Framework Fingerprinting")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 5: Web Technology & CMS Fingerprinting")
            tech_res = fingerprint_technology(domain, timeout=timeout * 4)
            report["technologies"] = tech_res
            display_tech_results(tech_res)
        else:
            report["technologies"] = {"status": "skipped"}
            log_info("Stage 5: Technology Fingerprinting skipped.")

        # Stage 6: Sensitive Endpoints & File Disclosure
        proceed = True if not staged else prompt_stage("Stage 6: Sensitive Files & Endpoint Discovery")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 6: Sensitive Files & Endpoint Probing")
            endpoints_res = audit_sensitive_endpoints(domain, timeout=timeout * 3)
            report["endpoints"] = endpoints_res
            display_endpoints_results(endpoints_res)
        else:
            report["endpoints"] = {"status": "skipped"}
            log_info("Stage 6: Endpoint Discovery skipped.")

        # Stage 7: Port Reachability Audit
        proceed = True if not staged else prompt_stage("Stage 7: Common Service Reachability Audit")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 7: Port Reachability & Common Services")
            dns_res = resolve_domain(domain)
            target_ip = dns_res.get("primary_ip")
            report["dns"] = dns_res

            if target_ip:
                log_info(f"Scanning common service ports on {target_ip} with {workers} threads...")
                port_res = scan_ports(target_ip, timeout=timeout, max_workers=workers)
                report["ports"] = port_res
                display_ports_results(port_res)
            else:
                log_error("Cannot execute port check: Domain resolution failed.")
                report["ports"] = {"status": "error", "message": "Domain resolution failed"}
        else:
            report["ports"] = {"status": "skipped"}
            log_info("Stage 7: Port Reachability skipped.")

        # Stage 8: Passive Subdomain Enumeration
        proceed = True if not staged else prompt_stage("Stage 8: Passive Subdomain Discovery (Certificate Logs & OSINT)")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 8: Passive Subdomain Discovery")
            log_info("Querying certificate transparency logs & passive OSINT engines...")
            sub_res = query_subdomains_crtsh(domain, timeout=timeout * 5)
            report["subdomains"] = sub_res
            display_subdomains_results(sub_res)
        else:
            report["subdomains"] = {"status": "skipped"}
            log_info("Stage 8: Subdomain Discovery skipped.")

        # Stage 9: WHOIS & ASN Threat Intelligence
        proceed = True if not staged else prompt_stage("Stage 9: WHOIS & ASN Threat Intelligence")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 9: WHOIS, ASN & Network Intelligence")
            dns_res = resolve_domain(domain)
            primary_ip = dns_res.get("primary_ip")
            intel_res = gather_network_intel(domain, ip=primary_ip, timeout=timeout * 3.5)
            report["threat_intel"] = intel_res
            display_intel_results(intel_res)
        else:
            report["threat_intel"] = {"status": "skipped"}
            log_info("Stage 9: Threat Intelligence skipped.")

        # Stage 10: URLs & Query Parameter Discovery
        proceed = True if not staged else prompt_stage("Stage 10: Passive URLs & Query Parameter Discovery")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Stage 10: URLs & Query Parameter Discovery")
            log_info("Mining passive web archives and indicators for endpoints and parameters...")
            url_res = gather_domain_urls(domain, timeout=timeout * 5)
            report["urls_discovery"] = url_res
            display_urls_results(url_res)
        else:
            report["urls_discovery"] = {"status": "skipped"}
            log_info("Stage 10: URL Discovery skipped.")

    elif mode == "attacker":
        log_info("Engaging Attacker / Bug Bounty Vulnerability Hunting Workflow...")
        
        proceed = True if not staged else prompt_stage("Attacker Stage A: Passive URL & Parameter Harvesting")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Attacker Stage A: URL & Parameter Harvesting for Bugs")
            url_res = gather_domain_urls(domain, timeout=timeout * 5)
            report["urls_discovery"] = url_res
            display_urls_results(url_res)
        else:
            report["urls_discovery"] = {"status": "skipped"}
            log_info("URL Harvesting skipped.")

        proceed = True if not staged else prompt_stage("Attacker Stage B: Bug Bounty Payload & Vector Generation (XSS, SQLi, IDOR)")
        if proceed is None:
            save_reports(domain, report, output_dir)
            return
        elif proceed:
            print_section_header("Attacker Stage B: Bug Bounty Payload Generation")
            log_info("Constructing targeted XSS, SQL injection, and IDOR payload URLs to find bugs & earn bounties...")
            param_urls = report.get("urls_discovery", {}).get("parameterized_urls", [])
            if not param_urls:
                log_info("No parameterized URLs from current harvest. Gathering fresh URLs...")
                url_res = gather_domain_urls(domain, timeout=timeout * 5)
                report["urls_discovery"] = url_res
                param_urls = url_res.get("parameterized_urls", [])
            
            vuln_res = generate_vuln_payload_urls(param_urls)
            report["vuln_urls"] = vuln_res
            display_vuln_urls_results(vuln_res)
        else:
            report["vuln_urls"] = {"status": "skipped"}
            log_info("Vulnerability Vector Generation skipped.")

    print_section_header("Assessment Summary & Reports")
    saved_path = save_reports(domain, report, output_base=output_dir)
    log_success(f"Deliverables saved to: {saved_path}/")
    log_info("Check generated files for findings, URLs, and bug bounty payloads.\n")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Security Reconnaissance & Bug Bounty CLI"
    )
    parser.add_argument("-d", "--domain", help="Target domain to scan (e.g. example.com)")
    parser.add_argument("--mode", choices=["recon", "attacker"], help="Operation mode: 'recon' or 'attacker'")
    parser.add_argument("--non-interactive", action="store_true", help="Run stages continuously without interactive prompts")
    parser.add_argument("-o", "--output", default="reports", help="Directory path for saving assessment reports")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Base socket timeout in seconds (default: 1.5)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Concurrent threads for scanning (default: 10)")

    args = parser.parse_args()
    domain = args.domain

    if not domain:
        try:
            domain = input("Enter target domain to assess: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

    if not domain:
        print("Error: Target domain is required.", file=sys.stderr)
        sys.exit(1)

    clean_domain = clean_target_domain(domain)
    
    mode = args.mode
    if not mode and not args.non_interactive:
        mode = prompt_mode()
        if not mode:
            print("\nExiting.")
            sys.exit(0)
    elif not mode:
        mode = "recon"

    try:
        execute_recon(
            domain=clean_domain,
            mode=mode,
            staged=not args.non_interactive,
            output_dir=args.output,
            timeout=args.timeout,
            workers=args.workers
        )
    except KeyboardInterrupt:
        log_warn("\nExecution interrupted by user. Exiting cleanly.")
        sys.exit(130)

if __name__ == "__main__":
    main()
