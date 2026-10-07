import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch"
}

def _scan_single_port(ip, port, service_name, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((ip, port))
        is_open = (code == 0)
        return port, service_name, ("open" if is_open else "closed"), None
    except Exception as e:
        return port, service_name, "error", str(e)
    finally:
        sock.close()

def scan_ports(target_ip, ports_dict=None, timeout=1.2, max_workers=10):
    """Scans target ports using concurrent TCP handshake workers."""
    ports_to_scan = ports_dict or COMMON_PORTS
    results = {}
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_scan_single_port, target_ip, p, svc, timeout): p
            for p, svc in ports_to_scan.items()
        }

        for future in as_completed(future_to_port):
            port, svc, state, err = future.result()
            results[port] = {
                "service": svc,
                "state": state
            }
            if err:
                results[port]["error"] = err
            if state == "open":
                open_ports.append({"port": port, "service": svc})

    open_ports.sort(key=lambda x: x["port"])
    return {
        "status": "success",
        "scanned_count": len(ports_to_scan),
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "details": dict(sorted(results.items()))
    }
