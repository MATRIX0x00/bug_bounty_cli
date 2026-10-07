import ssl
import socket
from datetime import datetime, timezone

def inspect_ssl(domain, port=443, timeout=6.0):
    """Fetches and analyzes SSL/TLS certificate details."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                alt_names = [val for key, val in cert.get("subjectAltName", []) if key == "DNS"]

                not_after_str = cert.get("notAfter")
                expired = False
                days_remaining = None
                if not_after_str:
                    # Format e.g.: Dec 25 22:56:35 2026 GMT
                    expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    delta = expiry_date - now_utc
                    days_remaining = delta.days
                    expired = delta.total_seconds() <= 0

                return {
                    "status": "success",
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "tls_version": tls_version,
                    "cipher_suite": cipher[0] if cipher else None,
                    "subject": subject,
                    "issuer": issuer,
                    "subject_alt_names": alt_names,
                    "not_before": cert.get("notBefore"),
                    "not_after": not_after_str,
                    "days_remaining": days_remaining,
                    "is_expired": expired
                }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
