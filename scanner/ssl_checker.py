
import socket
import ssl
import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from bs4 import BeautifulSoup

class SSLChecker:
    def __init__(self, target_url, progress_callback=None, request_timeout=10):
        self.target_url = target_url
        self.progress_callback = progress_callback
        self.request_timeout = request_timeout

        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc
        if ':' in self.hostname:
            self.hostname = self.hostname.split(':')[0]
        self.port = self.parsed_url.port or 443

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OmenSight Scanner/1.0"})


    def _log(self, message, level="info"):
        """Helper for logging to console and GUI callback."""
        prefix_map = {"info": "[+]", "progress": "[~]", "vuln": "[!]", "warn": "[!]", "error": "[-]"}
        prefix = prefix_map.get(level, "[?]")
        full_message = f"{prefix} SSLCheck: {message}"
        print(full_message)
        if self.progress_callback and level in ["progress", "info", "warn", "error", "vuln"]:
            self.progress_callback(full_message)

    def get_ssl_info(self):
        """Retrieves SSL certificate, negotiated protocol, and cipher from the target."""
        if self.parsed_url.scheme.lower() != "https":
            return {"error": "Target URL is not HTTPS. SSL/TLS scan not applicable."}
        if not self.hostname:
            return {"error": "Could not determine hostname from URL."}

        self._log(f"Attempting SSL connection to {self.hostname}:{self.port} (with hostname verification)", level="progress")
        context = ssl.create_default_context()

        try:
            with socket.create_connection((self.hostname, self.port), timeout=self.request_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher_details = ssock.cipher()
                    self._log("SSL connection successful, verification passed.", level="info")
                    return {
                        "certificate": cert, "protocol": protocol,
                        "cipher_name": cipher_details[0] if cipher_details else "N/A",
                        "cipher_protocol": cipher_details[1] if cipher_details else "N/A",
                        "cipher_bits": cipher_details[2] if cipher_details else "N/A",
                        "hostname_match": True, "verification_error": None, "error": None
                    }
        except ssl.SSLCertVerificationError as e:
            reason = getattr(e, 'reason', str(e))
            verify_message = getattr(e, 'verify_message', '')
            log_message = f"SSL Certificate Verification Error for {self.hostname}: {reason} - {verify_message}"
            self._log(log_message, level="warn")
            hostname_mismatch = False
            if "hostname mismatch" in verify_message.lower() or "certificate is not valid for" in verify_message.lower():
                 hostname_mismatch = True
            return {
                "error": f"SSL Certificate Verification Error: {reason}", "verification_error": reason,
                "hostname_match": not hostname_mismatch, "certificate": None, "protocol": None, "cipher_name": None
            }
        except socket.timeout:
            self._log(f"Connection to {self.hostname}:{self.port} timed out.", level="error")
            return {"error": "Connection timed out."}
        except socket.gaierror:
            self._log(f"Could not resolve hostname: {self.hostname}.", level="error")
            return {"error": f"Could not resolve hostname: {self.hostname}."}
        except ssl.SSLError as e:
            reason = getattr(e, 'reason', str(e))
            self._log(f"SSL Error connecting to {self.hostname}:{self.port}: {reason}", level="error")
            return {"error": f"SSL Error: {reason}"}
        except ConnectionRefusedError:
            self._log(f"Connection refused by {self.hostname}:{self.port}.", level="error")
            return {"error": "Connection refused."}
        except Exception as e:
            self._log(f"Unexpected error retrieving SSL info from {self.hostname}:{self.port}: {e}", level="error")
            return {"error": f"Unexpected error: {e}"}

    def scan_ssl_details(self):
        """Scans the target for SSL/TLS configurations and certificate details."""
        self._log(f"Starting SSL/TLS scan for {self.target_url}...", level="info")
        output_lines = [f"SSL/TLS Scan Report for: {self.target_url} ({self.hostname}:{self.port})"]
        ssl_info = self.get_ssl_info()

        if ssl_info.get("error") and not ssl_info.get("verification_error"):
            output_lines.append(f"[!] Error: {ssl_info['error']}")
            self._log("SSL scan finished due to error.", level="info")
            return "\n".join(output_lines)

        if ssl_info.get("verification_error"):
             output_lines.append("-" * 30)
             output_lines.append("[+] Connection/Verification Status:")
             output_lines.append(f"    [!] Verification Failed: {ssl_info['verification_error']}")

        protocol = ssl_info.get("protocol")
        cipher_name = ssl_info.get("cipher_name")
        if protocol or cipher_name or ssl_info.get("verification_error"):
            if not ssl_info.get("verification_error"):
                 output_lines.append("-" * 30)
                 output_lines.append("[+] Connection Details:")

            output_lines.append(f"    Negotiated Protocol: {protocol if protocol else 'N/A'}")
            output_lines.append(f"    Negotiated Cipher: {cipher_name if cipher_name else 'N/A'}")
            if protocol:
                if protocol in ["TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]:
                    output_lines.append(f"    [!] Weak Protocol: {protocol} is outdated and insecure.")
                    self._log(f"Weak protocol {protocol} detected.", level="vuln")
                elif protocol in ["TLSv1.2", "TLSv1.3"]:
                    output_lines.append(f"    [+] Strong Protocol: {protocol} is considered secure.")

        cert = ssl_info.get("certificate")
        output_lines.append("-" * 30)
        output_lines.append("[+] Certificate Details:")
        if not cert:
            reason = "Verification failed" if ssl_info.get("verification_error") else "Connection/Retrieval failed"
            output_lines.append(f"    Could not retrieve certificate details ({reason}).")
        else:

            subject_str = ", ".join([f"{item[0][0]}={item[0][1]}" for item in cert.get('subject', [])])
            issuer_str = ", ".join([f"{item[0][0]}={item[0][1]}" for item in cert.get('issuer', [])])
            output_lines.append(f"    Subject: {subject_str if subject_str else 'N/A'}")
            output_lines.append(f"    Issuer: {issuer_str if issuer_str else 'N/A'}")

            if cert.get("issuer") == cert.get("subject"):
                output_lines.append("    [!] Certificate appears to be self-signed.")
                self._log("Self-signed certificate detected.", level="vuln")

            if 'notBefore' in cert:
                 try:
                      start_timestamp = ssl.cert_time_to_seconds(cert['notBefore'])
                      start_datetime = datetime.fromtimestamp(start_timestamp, tz=timezone.utc)
                      output_lines.append(f"    Valid From:  {start_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                 except Exception as e:
                      output_lines.append(f"    Could not parse start date: {cert['notBefore']} (Error: {e})")

            if 'notAfter' in cert:
                try:
                    expiry_timestamp = ssl.cert_time_to_seconds(cert['notAfter'])
                    expiry_datetime = datetime.fromtimestamp(expiry_timestamp, tz=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    output_lines.append(f"    Valid Until: {expiry_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                    if expiry_datetime < now_utc:
                        output_lines.append("    [!] Certificate has EXPIRED!")
                        self._log("Expired certificate detected.", level="vuln")
                    else:
                        days_left = (expiry_datetime - now_utc).days
                        output_lines.append(f"    [+] Certificate is valid (Expires in {days_left} days).")
                except Exception as e:
                    output_lines.append(f"    Could not parse expiration date: {cert['notAfter']} (Error: {e})")

            hostname_match_passed = ssl_info.get("hostname_match")
            if hostname_match_passed is True:
                 output_lines.append("    [+] Certificate hostname check passed (during handshake).")
            elif hostname_match_passed is False:
                 output_lines.append(f"    [!] Certificate hostname MISMATCH for '{self.hostname}' (detected during handshake).")
                 self._log(f"Certificate hostname mismatch for '{self.hostname}'.", level="vuln")
            else:
                 output_lines.append(f"    [?] Certificate hostname check inconclusive (Verification Error: {ssl_info.get('verification_error', 'Unknown')})")

            if 'serialNumber' in cert:
                output_lines.append(f"    Serial Number: {cert['serialNumber']}")

            if 'subjectAltName' in cert:
                sans = [item[1] for item in cert['subjectAltName'] if item[0].lower() == 'dns']
                if sans:
                     output_lines.append("    Subject Alt Names (DNS):")
                     for name in sans:
                          output_lines.append(f"        {name}")
                else:
                     output_lines.append("    Subject Alt Names (DNS): None found")
            else:
                 output_lines.append("    Subject Alt Names (DNS): Not present in certificate")


        output_lines.append("-" * 30)
        self._log("SSL scan finished.", level="info")
        return "\n".join(output_lines)

def scan_ssl(target_url, progress_callback=None):
    """Scans the target website for SSL/TLS configurations. Wrapper for SSLChecker."""
    checker = SSLChecker(target_url, progress_callback=progress_callback)
    return checker.scan_ssl_details()

if __name__ == '__main__':
    target = "https://google.com"

    print(f"--- Testing SSLChecker on {target} ---")
    def simple_callback_for_test(message):
        print(f"UI_CALLBACK: {message}")
    results = scan_ssl(target, progress_callback=simple_callback_for_test)
    print("\n--- Scan Results ---")
    print(results)
 