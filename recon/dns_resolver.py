import socket

def resolve_domain(domain):
    """Resolves domain to IPv4 addresses and reverse lookup hostnames."""
    try:
        addr_info = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted(list({item[4][0] for item in addr_info}))
        primary_ip = ips[0] if ips else None

        reverse_name = None
        if primary_ip:
            try:
                reverse_name = socket.gethostbyaddr(primary_ip)[0]
            except (socket.herror, socket.gaierror):
                reverse_name = None

        return {
            "status": "success",
            "domain": domain,
            "primary_ip": primary_ip,
            "all_ips": ips,
            "reverse_hostname": reverse_name
        }
    except socket.gaierror as e:
        return {
            "status": "error",
            "domain": domain,
            "message": str(e)
        }
