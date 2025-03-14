import socket
import ssl

def get_ssl_certificate_info(target_url):
    """Retrieve SSL certificate details from the target website."""
    try:
        hostname = target_url.replace("https://", "").replace("http://", "").split("/")[0]
        port = 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return f"Error retrieving SSL certificate: {e}"

def scan_ssl(target_url):
    """Scan the target website for basic SSL vulnerabilities."""
    print(f"\n[+] Scanning {target_url} for SSL/TLS vulnerabilities...")
    cert_info = get_ssl_certificate_info(target_url)

    if isinstance(cert_info, str):
        return cert_info  # Return the error message if SSL certificate couldn't be retrieved

    vulnerabilities = []

    # Check for self-signed certificate
    if "issuer" in cert_info and cert_info["issuer"] == cert_info.get("subject"):
        vulnerabilities.append("Self-signed certificate detected, which may indicate security risks.")

    # Check for outdated TLS versions
    tls_version = cert_info.get("version", "")
    if isinstance(tls_version, str) and "TLSv1" in tls_version:
        vulnerabilities.append("TLS 1.0 detected. This protocol is outdated and insecure.")

    return vulnerabilities if vulnerabilities else "No critical SSL vulnerabilities found."