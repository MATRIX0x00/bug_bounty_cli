import sys

class TerminalColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"

def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def colorize(text, color_code):
    if supports_color():
        return f"{color_code}{text}{TerminalColors.RESET}"
    return text

def print_banner():
    banner = r"""
    ____                          ________    ____
   / __ —_________  ____     / ____/ /   /  _/
  / /_/ / _ \/ ___/ __ \/ __ \   / /   / /    / /  
 / _, _/  __/ /__/ /_/ / / / /  / /___/ /____/ /   
/_/ |_|\___/\___/\____/_/ /_/   \____/_____/___/   
    """
    print(colorize(banner, TerminalColors.CYAN))
    print(colorize("   [ Advanced Security & Reconnaissance Framework v2.2 ]\n", TerminalColors.BOLD))

def log_info(msg):
    print(f"{colorize('[*]', TerminalColors.BLUE)} {msg}")

def log_success(msg):
    print(f"{colorize('[+]', TerminalColors.GREEN)} {msg}")

def log_warn(msg):
    print(f"{colorize('[!]', TerminalColors.YELLOW)} {msg}")

def log_error(msg):
    print(f"{colorize('[-]', TerminalColors.RED)} {msg}")

def print_section_header(title):
    bar = "=" * 60
    print(f"\n{colorize(bar, TerminalColors.CYAN)}")
    print(f"{colorize(f'[*] {title}', TerminalColors.BOLD)}")
    print(colorize(bar, TerminalColors.CYAN))

def display_dns_results(dns_res):
    if dns_res.get("status") != "success":
        log_error(f"DNS Resolution failed: {dns_res.get('message')}")
        return
    print(f"  {colorize('Primary IPv4:', TerminalColors.BOLD)}      {dns_res.get('primary_ip', 'N/A')}")
    ips = dns_res.get('all_ips', [])
    print(f"  {colorize('All Resolved IPs:', TerminalColors.BOLD)}  {', '.join(ips) if ips else 'None'}")
    print(f"  {colorize('Reverse PTR Host:', TerminalColors.BOLD)}  {dns_res.get('reverse_hostname') or 'None detected'}")

def display_dns_advanced_results(dns_adv_res):
    if dns_adv_res.get("status") != "success":
        log_warn("Advanced DNS records query returned no data.")
        return
    email_sec = dns_adv_res.get("email_security", {})
    spf = email_sec.get("spf", {})
    dmarc = email_sec.get("dmarc", {})
    mx = email_sec.get("mx_servers", [])
    
    print(f"  {colorize('Mail Servers (MX):', TerminalColors.BOLD)} {', '.join(mx) if mx else 'None found'}")
    
    spf_str = colorize("Found", TerminalColors.GREEN) if spf.get("configured") else colorize("Missing", TerminalColors.RED)
    print(f"  {colorize('SPF Record:', TerminalColors.BOLD)}       {spf_str} ({spf.get('risk', 'N/A')})")
    if spf.get("policy"):
        print(f"    {colorize('Policy:', TerminalColors.GRAY)} {spf.get('policy')}")
        
    dmarc_str = colorize("Found", TerminalColors.GREEN) if dmarc.get("configured") else colorize("Missing", TerminalColors.RED)
    print(f"  {colorize('DMARC Record:', TerminalColors.BOLD)}     {dmarc_str} ({dmarc.get('risk', 'N/A')})")
    if dmarc.get("policy"):
        print(f"    {colorize('Policy:', TerminalColors.GRAY)} {dmarc.get('policy')}")

def display_ssl_results(ssl_res):
    if ssl_res.get("status") != "success":
        log_warn(f"SSL/TLS check notice: {ssl_res.get('message')}")
        return
    print(f"  {colorize('TLS Version:', TerminalColors.BOLD)}       {ssl_res.get('tls_version', 'N/A')}")
    print(f"  {colorize('Cipher Suite:', TerminalColors.BOLD)}      {ssl_res.get('cipher_suite', 'N/A')}")
    days = ssl_res.get('days_remaining')
    days_str = f"{days} days remaining" if days is not None else "N/A"
    if ssl_res.get('is_expired'):
        days_str = colorize(f"EXPIRED ({days_str})", TerminalColors.RED)
    else:
        days_str = colorize(days_str, TerminalColors.GREEN)
    print(f"  {colorize('Cert Validity:', TerminalColors.BOLD)}     {days_str}")
    print(f"  {colorize('Valid Until:', TerminalColors.BOLD)}       {ssl_res.get('not_after', 'N/A')}")
    sans = ssl_res.get('subject_alt_names', [])
    print(f"  {colorize('SAN Count:', TerminalColors.BOLD)}         {len(sans)}")
    if sans:
        sample_sans = sans[:6]
        print(f"  {colorize('SAN Sample:', TerminalColors.BOLD)}        {', '.join(sample_sans)}{'...' if len(sans) > 6 else ''}")

def display_headers_results(hdr_res):
    if hdr_res.get("status") != "success":
        log_error(f"HTTP probe failed: {hdr_res.get('message')}")
        return
    print(f"  {colorize('Final URL:', TerminalColors.BOLD)}         {hdr_res.get('final_url', 'N/A')}")
    print(f"  {colorize('HTTP Status:', TerminalColors.BOLD)}       {hdr_res.get('status_code', 'N/A')}")
    print(f"  {colorize('Server Header:', TerminalColors.BOLD)}     {hdr_res.get('server', 'N/A')}")
    print(f"  {colorize('Security Score:', TerminalColors.BOLD)}    {hdr_res.get('security_score', 'N/A')}")
    
    present = hdr_res.get("security_headers_present", {})
    missing = hdr_res.get("security_headers_missing", [])
    
    print(f"  {colorize('Present Headers:', TerminalColors.BOLD)}   {len(present)}")
    for h, v in present.items():
        print(f"    {colorize('✔', TerminalColors.GREEN)} {h}: {v[:50]}{'...' if len(v) > 50 else ''}")
        
    print(f"  {colorize('Missing Headers:', TerminalColors.BOLD)}   {len(missing)}")
    for h in missing:
        print(f"    {colorize('✘', TerminalColors.RED)} {h}")

def display_tech_results(tech_res):
    if tech_res.get("status") != "success":
        log_warn(f"Technology detection notice: {tech_res.get('message')}")
        return
    print(f"  {colorize('Web Server:', TerminalColors.BOLD)}        {tech_res.get('server', 'Unknown')}")
    print(f"  {colorize('Backend / Power:', TerminalColors.BOLD)}    {tech_res.get('x_powered_by', 'Hidden')}")
    print(f"  {colorize('CMS Detection:', TerminalColors.BOLD)}      {tech_res.get('detected_cms', 'N/A')}")
    techs = tech_res.get('technologies', [])
    print(f"  {colorize('Technologies:', TerminalColors.BOLD)}       {', '.join(techs) if techs else 'None identified'}")

def display_endpoints_results(end_res):
    if end_res.get("status") != "success":
        log_warn("Endpoint discovery encountered an issue.")
        return
    accessible = end_res.get("accessible_endpoints", [])
    print(f"  {colorize('Accessible Sensitive Files:', TerminalColors.BOLD)} {len(accessible)}")
    for item in accessible:
        color = TerminalColors.RED if item['path'] in ['/.env', '/.git/HEAD'] else TerminalColors.GREEN
        print(f"    {colorize('✔', color)} {item['path']} ({item['name']}) [HTTP {item['code']}]")
    
    disallowed = end_res.get("robots_disallowed_entries", [])
    if disallowed:
        print(f"  {colorize('Robots.txt Disallowed Samples:', TerminalColors.BOLD)}")
        for d in disallowed[:5]:
            print(f"    {colorize('•', TerminalColors.YELLOW)} {d}")

def display_ports_results(port_res):
    if port_res.get("status") != "success":
        log_error(f"Port scan failed: {port_res.get('message')}")
        return
    open_ports = port_res.get("open_ports", [])
    scanned = port_res.get("scanned_count", 0)
    print(f"  {colorize('Scanned Ports:', TerminalColors.BOLD)}     {scanned}")
    print(f"  {colorize('Open Ports:', TerminalColors.BOLD)}        {len(open_ports)}")
    if open_ports:
        print("    PORT      SERVICE      STATE")
        print("    " + "-" * 30)
        for item in open_ports:
            print(f"    {colorize(str(item['port']).ljust(8), TerminalColors.GREEN)}  {item['service'].ljust(11)}  {colorize('OPEN', TerminalColors.GREEN)}")
    else:
        print(f"    {colorize('No open ports found among tested common services.', TerminalColors.YELLOW)}")

def display_subdomains_results(sub_res):
    if sub_res.get("status") != "success":
        log_warn(f"Subdomain discovery notice: {sub_res.get('message')}")
        return
    subs = sub_res.get("subdomains", [])
    sources = ", ".join(sub_res.get("active_sources", [])) or "Passive cert logs"
    print(f"  {colorize('Active Sources:', TerminalColors.BOLD)}   {sources}")
    print(f"  {colorize('Total Discovered:', TerminalColors.BOLD)} {len(subs)}")
    if subs:
        sample = subs[:15]
        for s in sample:
            print(f"    {colorize('•', TerminalColors.CYAN)} {s}")
        if len(subs) > 15:
            print(f"    {colorize(f'... and {len(subs) - 15} more in reports.', TerminalColors.GRAY)}")

def display_intel_results(intel_res):
    if intel_res.get("status") != "success":
        log_warn("Network intelligence lookup unavailable.")
        return
    print(f"  {colorize('ASN:', TerminalColors.BOLD)}               {intel_res.get('asn', 'N/A')}")
    print(f"  {colorize('Organization:', TerminalColors.BOLD)}      {intel_res.get('org', 'N/A')}")
    print(f"  {colorize('ISP:', TerminalColors.BOLD)}               {intel_res.get('isp', 'N/A')}")
    print(f"  {colorize('Location:', TerminalColors.BOLD)}          {intel_res.get('city', 'N/A')}, {intel_res.get('country', 'N/A')}")
    print(f"  {colorize('Registrar:', TerminalColors.BOLD)}         {intel_res.get('registrar', 'N/A')}")

def display_urls_results(url_res):
    if url_res.get("status") != "success":
        log_warn("URL discovery query returned no results.")
        return
    sources = ", ".join(url_res.get("active_sources", [])) or "Passive archives"
    total = url_res.get("total_urls", 0)
    param_count = url_res.get("total_parameterized", 0)
    unique_params = url_res.get("unique_parameters", [])
    
    print(f"  {colorize('Active Sources:', TerminalColors.BOLD)}      {sources}")
    print(f"  {colorize('Total URLs Discovered:', TerminalColors.BOLD)} {total}")
    print(f"  {colorize('Parameterized URLs:', TerminalColors.BOLD)}   {param_count}")
    print(f"  {colorize('Discovered Parameters:', TerminalColors.BOLD)} {len(unique_params)} distinct keys")
    if unique_params:
        param_sample = unique_params[:12]
        print(f"    {colorize('Params:', TerminalColors.GRAY)} {', '.join(param_sample)}{'...' if len(unique_params) > 12 else ''}")
    
    sample_urls = url_res.get("sample_urls", [])
    if sample_urls:
        print(f"\n  {colorize('Discovered URLs Sample (Showing up to 10 lines):', TerminalColors.BOLD)}")
        for u in sample_urls[:10]:
            print(f"    {colorize('•', TerminalColors.CYAN)} {u}")
        if total > 10:
            print(f"    {colorize(f'... and {total - 10} more written to urls.txt and reports.', TerminalColors.GRAY)}")

def display_vuln_urls_results(vuln_res):
    if vuln_res.get("status") != "success":
        log_warn("Vulnerability vector generation notice: No parameterized URLs found.")
        return
    print(f"  {colorize('Generated XSS URLs:', TerminalColors.BOLD)}       {vuln_res.get('xss_count', 0)}")
    print(f"  {colorize('Generated SQLi URLs:', TerminalColors.BOLD)}      {vuln_res.get('sqli_count', 0)}")
    print(f"  {colorize('Generated IDOR Vectors:', TerminalColors.BOLD)}    {vuln_res.get('idor_count', 0)}")

def prompt_stage(stage_name):
    while True:
        prompt_text = f"\n{colorize('[?]', TerminalColors.MAGENTA)} Proceed to {stage_name}? (y/n/q): "
        choice = input(prompt_text).strip().lower()
        if choice in ["y", "yes"]:
            return True
        elif choice in ["n", "no"]:
            return False
        elif choice in ["q", "quit"]:
            log_warn("Aborting remaining stages per user request.")
            return None
        print("Please enter 'y' to proceed, 'n' to skip, or 'q' to abort.")
