import requests
from urllib.parse import urlparse, urljoin
import re

class OpenRedirectScanner:
    def __init__(self, target_url):
        """Initialize Open Redirect Scanner."""
        self.target_url = target_url
        self.redirect_params = ["next", "url", "redirect", "return", "go"]
        self.payloads =self.load_payloads("static/open_direct_payloads.txt")

    def load_payloads(self, file_path):
        """Load Open Redirect payloads from a file in static/ directory."""
        try:
            with open(file_path, "r",encoding="utf-8") as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            print("[-] Payload file not found. Using default payloads.")
            return [
                "http://evil.com", "https://malicious.com", "//evil.com",
                "//google.com", "https:evil.com", "http://127.0.0.1"
            ]
        except UnicodeDecodeError as e:
            print(f"[-] Error reading payload file: {str(e)}")
            return [
                "http://evil.com", "https://malicious.com", "//evil.com",
                "//google.com", "https:evil.com", "http://127.0.0.1"
            ]

    def scan(self):
        """Scan for Open Redirect vulnerabilities."""
        print(f"\n[+] Scanning {self.target_url} for Open Redirect vulnerabilities...")
        detected_vulns = []

        for param in self.redirect_params:
            for payload in self.payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                try:
                    response = requests.get(test_url, allow_redirects=True, timeout=5)
                    final_url = response.url

                    # Check if the response redirects to an external domain
                    if urlparse(final_url).netloc not in urlparse(self.target_url).netloc:
                        print(f"⚠ Potential Open Redirect detected: {test_url} -> {final_url}")
                        detected_vulns.append((test_url, final_url))
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {test_url}: {str(e)}")

        return detected_vulns if detected_vulns else "No Open Redirect vulnerabilities found."