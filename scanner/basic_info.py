import socket
import requests
import whois
import dns.resolver
from urllib.parse import urlparse

class BasicInfoScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc

    def get_ip(self):
        try:
            return socket.gethostbyname(self.domain)
        except socket.gaierror:
            return "Unable to resolve IP"

    def get_whois_info(self):
        try:
            info = whois.whois(self.domain)
            return str(info)
        except Exception as e:
            return f"Whois lookup failed: {str(e)}"

    def dns_lookup(self):
        result = {}
        try:
            a_records = dns.resolver.resolve(self.domain, 'A')
            result['A'] = [r.to_text() for r in a_records]
        except:
            result['A'] = []

        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            result['MX'] = [r.exchange.to_text() for r in mx_records]
        except:
            result['MX'] = []

        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            result['NS'] = [r.to_text() for r in ns_records]
        except:
            result['NS'] = []

        return result

    def ip_location_lookup(self, ip_address):
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def scan(self):
        output = []
        ip_address = self.get_ip()
        output.append(f"[+] IP Address: {ip_address}")

        whois_info = self.get_whois_info()
        output.append(f"[+] WHOIS Info:\n{whois_info}")

        dns_info = self.dns_lookup()
        output.append(f"[+] DNS Records:")
        for record_type, values in dns_info.items():
            output.append(f"    {record_type}: {', '.join(values) if values else 'None'}")

        location_info = self.ip_location_lookup(ip_address)
        output.append("[+] IP Geolocation Info:")
        for key, value in location_info.items():
            output.append(f"    {key}: {value}")

        return "\n".join(output)
