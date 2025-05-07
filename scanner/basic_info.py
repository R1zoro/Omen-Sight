# --- START OF REVISED scanner/basic_info.py ---

import socket
import requests
import whois # type: ignore # Add this if your linter complains about whois import
import dns.resolver # type: ignore # Add this if your linter complains about dnspython
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup # For parsing HTML, e.g., for title

class BasicInfoScanner:
    def __init__(self, target_url, progress_callback=None, request_timeout=10):
        self.target_url = target_url
        self.progress_callback = progress_callback
        self.request_timeout = request_timeout
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "OmenSight Scanner/1.0"
        })
        # Allow scans on sites with self-signed or problematic SSL certs
        # Use with caution, implies not verifying SSL for this scanner's requests
        self.session.verify = False
        # Suppress InsecureRequestWarning if verify is False
        if not self.session.verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    def _log(self, message, level="info"):
        """Helper for logging to console and GUI callback."""
        prefix_map = {"info": "[+]", "progress": "[~]", "vuln": "[!]", "warn": "[!]", "error": "[-]"}
        prefix = prefix_map.get(level, "[?]")
        # Construct message carefully to avoid issues if message itself contains formatting chars
        full_message = f"{prefix} BasicInfo: {message}"
        print(full_message) # Always print to console
        if self.progress_callback and level in ["progress", "info", "warn", "error"]: # GUI updates for these
            self.progress_callback(full_message)

    def _make_request(self, url, stream=False, allow_redirects=True):
        """Internal helper to make GET requests using the session."""
        try:
            response = self.session.get(url, timeout=self.request_timeout, stream=stream, allow_redirects=allow_redirects)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response
        except requests.exceptions.HTTPError as e: # Specifically catch HTTP errors to get status code
            self._log(f"HTTP error for {url}: {e.response.status_code} {e.response.reason}", level="warn")
            return e.response # Return the response object even for HTTP errors (e.g., 404)
        except requests.exceptions.Timeout:
            self._log(f"Timeout connecting to {url}", level="error")
            return None
        except requests.exceptions.ConnectionError:
            self._log(f"Connection error for {url}", level="error")
            return None
        except requests.exceptions.RequestException as e:
            self._log(f"Request error for {url}: {e}", level="error")
            return None

    def get_ip(self):
        self._log(f"Resolving IP for {self.domain}", level="progress")
        try:
            ip = socket.gethostbyname(self.domain)
            self._log(f"IP for {self.domain} is {ip}", level="info")
            return ip
        except socket.gaierror:
            self._log(f"Unable to resolve IP for {self.domain}", level="error")
            return "Unable to resolve IP"

    def get_http_info(self):
        self._log(f"Fetching HTTP info from {self.target_url}", level="progress")
        response = self._make_request(self.target_url, allow_redirects=True) # Follow redirects for main page
        info = {"title": "Not found or error", "headers": {}}
        if response and response.status_code == 200: # Check for successful response
            try:
                # Page Title
                soup = BeautifulSoup(response.text, 'html.parser')
                title_tag = soup.find('title')
                if title_tag and title_tag.string:
                    info["title"] = title_tag.string.strip()
                else:
                    info["title"] = "No title tag found"

                # Key Headers
                key_headers = ['Server', 'X-Powered-By', 'Content-Type', 'Date', 'X-Frame-Options', 'Content-Security-Policy']
                for kh in key_headers:
                    if kh in response.headers:
                        info["headers"][kh] = response.headers[kh]
                self._log("Successfully fetched HTTP info.", level="info")
            except Exception as e:
                self._log(f"Error parsing HTTP info: {e}", level="error")
                # Keep default "Not found or error" for title
        elif response: # Response object exists but not 200 OK
             self._log(f"HTTP info request failed with status {response.status_code}", level="warn")
        else: # No response object
             self._log("HTTP info request failed (no response).", level="error")
        return info


    def check_robots_txt(self):
        robots_url = urljoin(self.target_url, "/robots.txt")
        self._log(f"Checking for robots.txt at {robots_url}", level="progress")
        response = self._make_request(robots_url, allow_redirects=False)

        if response is not None: # Check if we got a response object
            if response.status_code == 200:
                content = response.text
                summary = content.splitlines()[:15]
                if len(content.splitlines()) > 15:
                    summary.append("... (file truncated for summary)")
                self._log("robots.txt found and content retrieved.", level="info")
                return "\n".join(summary)
            elif response.status_code == 404:
                self._log("robots.txt not found (404).", level="info")
                return "Not found (404)"
            else:
                # _make_request already logged the HTTP error status
                return f"Received Status {response.status_code}"
        else: # _make_request returned None
            return "Error: Request failed (e.g., connection, timeout)."

    def check_sitemap_xml(self):
        sitemap_url = urljoin(self.target_url, "/sitemap.xml")
        self._log(f"Checking for sitemap.xml at {sitemap_url}", level="progress")
        response = self._make_request(sitemap_url, allow_redirects=False)

        if response is not None: # Check if we got a response object at all
            if response.status_code == 200:
                self._log("sitemap.xml found.", level="info")
                return "Found (Status 200)"
            elif response.status_code == 404:
                self._log("sitemap.xml not found (404).", level="info")
                return "Not found (404)"
            else:
                # _make_request already logged the HTTP error status
                # self._log(f"sitemap.xml check resulted in status {response.status_code}.", level="warn")
                return f"Received Status {response.status_code}" # More accurate message
        else: # _make_request returned None (e.g., connection error, timeout)
            # _make_request already logged the specific connection/timeout error
            return "Error: Request failed (e.g., connection, timeout)."


    def get_whois_info(self):
        if not self.domain:
            return "Invalid domain for WHOIS lookup."
        self._log(f"Performing WHOIS lookup for {self.domain}", level="progress")
        try:
            # Ensure domain is just the netloc, no scheme or path
            domain_for_whois = self.domain.split(':')[0] # Remove port if present
            info = whois.whois(domain_for_whois)
            # whois library can return a complex object or sometimes None/Error
            if info and (info.domain_name or info.registrar): # Check for some actual data
                self._log("WHOIS lookup successful.", level="info")
                # Convert to string, limit length for display
                str_info = str(info)
                return str_info[:2000] + ("..." if len(str_info) > 2000 else "")
            else:
                 self._log("WHOIS lookup returned no data or partial data.", level="warn")
                 return "WHOIS lookup returned no substantial data."
        except Exception as e:
            self._log(f"WHOIS lookup for {self.domain} failed: {e}", level="error")
            return f"WHOIS lookup failed: {str(e)}"

    def dns_lookup(self):
        if not self.domain:
            return {"error": "Invalid domain for DNS lookup."}
        self._log(f"Performing DNS lookup for {self.domain}", level="progress")
        results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']

        domain_for_dns = self.domain.split(':')[0] # Remove port if present

        for r_type in record_types:
            try:
                self._log(f"Querying {r_type} records...", level="progress")
                answers = dns.resolver.resolve(domain_for_dns, r_type)
                if r_type == 'MX':
                    results[r_type] = sorted([f"{r.preference} {r.exchange.to_text()}" for r in answers])
                elif r_type == 'TXT':
                    # TXT records can be multiple strings; join them
                    results[r_type] = [" ".join(s.decode('utf-8') for s in rdata.strings) for rdata in answers]
                else:
                    results[r_type] = sorted([r.to_text() for r in answers])
                self._log(f"Found {len(results[r_type])} {r_type} records.", level="info")
            except dns.resolver.NoAnswer:
                results[r_type] = []
                self._log(f"No {r_type} records found.", level="info")
            except dns.resolver.NXDOMAIN:
                self._log(f"Domain {domain_for_dns} does not exist (NXDOMAIN). Aborting further DNS lookups.", level="error")
                results[r_type] = ["NXDOMAIN"]
                # If domain doesn't exist, no point in querying other records for it
                for rt_remaining in record_types:
                    if rt_remaining not in results: results[rt_remaining] = ["NXDOMAIN"]
                break
            except dns.exception.Timeout:
                results[r_type] = ["Query Timed Out"]
                self._log(f"{r_type} record query timed out.", level="warn")
            except Exception as e: # Catch other dnspython or general errors
                results[r_type] = [f"Error: {type(e).__name__}"]
                self._log(f"Error querying {r_type} records: {e}", level="error")
        return results

    def ip_location_lookup(self, ip_address):
        if not ip_address or ip_address == "Unable to resolve IP":
            return {"error": "Invalid IP for geolocation lookup."}
        self._log(f"Performing IP geolocation lookup for {ip_address}", level="progress")
        try:
            # Use the session for consistency, although ipinfo.io is external
            response = self.session.get(f"https://ipinfo.io/{ip_address}/json", timeout=self.request_timeout)
            response.raise_for_status()
            self._log("IP geolocation lookup successful.", level="info")
            return response.json()
        except requests.exceptions.HTTPError as e:
             self._log(f"IP geolocation HTTP error: {e.response.status_code}", level="warn")
             return {"error": f"HTTP Error {e.response.status_code}", "details": e.response.text[:100]}
        except Exception as e:
            self._log(f"IP geolocation lookup for {ip_address} failed: {e}", level="error")
            return {"error": str(e)}

    def scan(self):
        """Main method to perform all basic information scans."""
        self._log(f"Starting basic information scan for {self.target_url}", level="info")
        output_lines = [f"Basic Information for: {self.target_url}"]

        # IP Address
        ip_address = self.get_ip()
        output_lines.append(f"[+] IP Address: {ip_address}")
        output_lines.append("-" * 30)


        # HTTP Info (Title, Headers)
        http_info_data = self.get_http_info()
        output_lines.append(f"[+] Page Title: {http_info_data.get('title', 'N/A')}")
        output_lines.append("[+] Key HTTP Headers:")
        if http_info_data.get('headers'):
            for header, value in http_info_data['headers'].items():
                output_lines.append(f"    {header}: {value}")
        else:
            output_lines.append("    No key headers found or error fetching.")
        output_lines.append("-" * 30)

        # Robots.txt
        robots_txt_content = self.check_robots_txt()
        output_lines.append(f"[+] Robots.txt Check:")
        output_lines.append(robots_txt_content if robots_txt_content else "    Error or not applicable.")
        output_lines.append("-" * 30)

        # Sitemap.xml
        sitemap_xml_status = self.check_sitemap_xml()
        output_lines.append(f"[+] Sitemap.xml Check: {sitemap_xml_status}")
        output_lines.append("-" * 30)

        # WHOIS Info
        whois_data = self.get_whois_info()
        output_lines.append(f"[+] WHOIS Info for {self.domain}:")
        output_lines.append(whois_data if whois_data else "    Error or not applicable.")
        output_lines.append("-" * 30)

        # DNS Records
        dns_records_data = self.dns_lookup()
        output_lines.append(f"[+] DNS Records for {self.domain}:")
        if dns_records_data.get("error"):
            output_lines.append(f"    Error: {dns_records_data['error']}")
        else:
            for record_type, values_list in dns_records_data.items():
                if values_list:
                    output_lines.append(f"    {record_type}:")
                    for val in values_list:
                        output_lines.append(f"        {val}")
                else:
                    output_lines.append(f"    {record_type}: None found")
        output_lines.append("-" * 30)

        # IP Geolocation
        if ip_address != "Unable to resolve IP":
            geolocation_data = self.ip_location_lookup(ip_address)
            output_lines.append(f"[+] IP Geolocation for {ip_address}:")
            if geolocation_data.get("error"):
                output_lines.append(f"    Error: {geolocation_data['error']}")
                if geolocation_data.get("details"):
                     output_lines.append(f"    Details: {geolocation_data['details']}")
            else:
                for key, value in geolocation_data.items():
                    output_lines.append(f"    {key.capitalize()}: {value}")
        else:
            output_lines.append("[+] IP Geolocation: Skipped (IP not resolved).")
        output_lines.append("-" * 30)

        self._log("Basic information scan finished.", level="info")
        return "\n".join(output_lines)

# Example usage (if run directly)
if __name__ == '__main__':
    target = "https://google.com" # Example target
    # target = "https://example.com"

    print(f"--- Testing BasicInfoScanner on {target} ---")

    def simple_callback_for_test(message):
        print(f"UI_CALLBACK: {message}") # Simulate GUI update

    scanner = BasicInfoScanner(target, progress_callback=simple_callback_for_test)
    results = scanner.scan()

    print("\n--- Scan Results ---")
    print(results)

# --- END OF REVISED scanner/basic_info.py ---