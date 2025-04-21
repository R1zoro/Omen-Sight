import concurrent.futures
import requests
from urllib.parse import urlparse

class OpenRedirectScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.redirect_params = ["next", "url", "redirect", "return", "go"]
        self.payloads = self.load_payloads("static/open_direct_payloads.txt")
        self.session = requests.Session()

    def load_payloads(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except:
            return ["http://evil.com", "//evil.com"]

    def threaded_scan(self):
        print(f"\n[+] Scanning {self.target_url} for Open Redirect vulnerabilities...")
        detected_vulns = []

        def test_payload(param, payload):
            test_url = f"{self.target_url}?{param}={payload}"
            try:
                response = self.session.get(test_url, allow_redirects=True, timeout=3)
                final_url = response.url
                if urlparse(final_url).netloc not in urlparse(self.target_url).netloc:
                    print(f"⚠ Potential Open Redirect detected: {test_url} ➜ {final_url}")
                    return f"{test_url} ➜ {final_url}"
            except requests.RequestException:
                return None

        tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for param in self.redirect_params:
                for payload in self.payloads:
                    tasks.append(executor.submit(test_payload, param, payload))

            for future in concurrent.futures.as_completed(tasks):
                result = future.result()
                if result:
                    detected_vulns.append(result)

        return "\n".join(detected_vulns) if detected_vulns else "No Open Redirect vulnerabilities found."
