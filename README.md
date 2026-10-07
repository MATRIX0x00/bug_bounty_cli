# Advanced Recon CLI

A modular, multi-threaded security reconnaissance framework designed for authorized penetration testing and bug bounty posture auditing.

## Architecture Overview

The codebase is organized into dedicated modular components within `recon/`:
- `recon/dns_resolver.py`: Stage 1: Forward IPv4 resolution and reverse PTR resolving.
- `recon/dns_advanced.py`: Stage 2: DNS records (MX, TXT, NS, SOA, AAAA) and email security assessment (SPF and DMARC spoofing evaluation) via DNS-over-HTTPS.
- `recon/ssl_inspector.py`: Stage 3: SSL/TLS inspection, certificate validity, expiration, and Subject Alternative Names (SANs).
- `recon/headers_auditor.py`: Stage 4: Evaluates HTTP security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy) and calculates a posture score.
- `recon/tech_stack.py`: Stage 5: Web technology, CMS (WordPress, Drupal, Shopify), server, and framework fingerprinting.
- `recon/endpoint_auditor.py`: Stage 6: Discovers standard sensitive endpoints (`robots.txt`, `sitemap.xml`, `security.txt`) and configuration exposures (`.git/HEAD`, `.env`, `.DS_Store`).
- `recon/port_scanner.py`: Stage 7: Multi-threaded TCP reachability engine with configurable worker threads.
- `recon/cert_transparency.py`: Stage 8: Passive subdomain discovery via Certificate Transparency logs (crt.sh) with AlienVault and HackerTarget failover.
- `recon/threat_intel.py`: Stage 9: ASN, IP Geolocation, ISP, and WHOIS/RDAP registrar intelligence.
- `recon/url_gatherer.py`: Stage 10: Passive historical URL mining (Wayback Machine, AlienVault OTX) and query parameter extraction.
- `recon/reporter.py`: Exports structured deliverables (`recon_report.json`, `summary.txt`, `report.md`, `urls.txt`, `urls_with_params.txt`).
- `recon/display.py`: Colorized terminal output and cleanly formatted section result displays.

## Installation

```bash
chmod +x install.sh
./install.sh
```

Or with pip:
```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode (Step-by-step confirmation)
```bash
python recon_cli.py -d example.com
```

### Non-Interactive Automation (Batch or automated runs)
```bash
python recon_cli.py -d example.com --non-interactive
```

### Advanced Options
```bash
python recon_cli.py -d example.com --non-interactive -w 20 -t 2.0 -o custom_reports
```

- `-d, --domain`: Target domain
- `--non-interactive`: Run all stages directly without interactive confirmation prompts
- `-w, --workers`: Number of concurrent threads for scanning (default: 10)
- `-t, --timeout`: Socket timeout in seconds (default: 1.5s)
- `-o, --output`: Directory to store generated reports (default: `reports/`)
