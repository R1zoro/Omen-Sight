# --- START OF REVISED scanner/security_checks.py ---

import requests
import ssl
import socket
import dns.resolver # type: ignore
import dns.exception # type: ignore
from urllib.parse import urlparse, urljoin
import re
from datetime import datetime # For HSTS check potentially

# Assuming progress_callback is passed and a _log function exists or is added.

class SecurityChecksScanner:
    # Add progress_callback and timeout
    def __init__(self, target_url, progress_callback=None, request_timeout=15):
        self.target_url = target_url
        self.progress_callback = progress_callback
        self.request_timeout = request_timeout

        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc
        # Remove port for DNS/Host checks
        if ':' in self.hostname:
            self.hostname = self.hostname.split(':')[0]

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "OmenSight Scanner/1.0"
        })
        # Allow scans on sites with self-signed or problematic SSL certs for header checks etc.
        self.session.verify = False
        if not self.session.verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.results = [] # Store findings as strings or dicts

    def _log(self, message, level="info"):
        """Helper for logging to console and GUI callback."""
        prefix_map = {"info": "[+]", "progress": "[~]", "vuln": "[!]", "warn": "[!]", "error": "[-]"}
        prefix = prefix_map.get(level, "[?]")
        full_message = f"{prefix} SecCheck: {message}"
        print(full_message)
        if self.progress_callback and level in ["progress", "info", "warn", "error", "vuln"]:
            self.progress_callback(full_message)

    def _make_request(self, url, method="get", allow_redirects=True, headers=None, stream=False):
        """Internal helper to make requests."""
        req_headers = self.session.headers.copy()
        if headers:
            req_headers.update(headers)
        try:
            if method.lower() == "head":
                 response = self.session.head(url, timeout=self.request_timeout, headers=req_headers, allow_redirects=allow_redirects)
            else: # Default to GET
                 response = self.session.get(url, timeout=self.request_timeout, headers=req_headers, allow_redirects=allow_redirects, stream=stream)
            # Don't raise for status here, as we want to analyze error responses too (like 404 for security.txt)
            return response
        except requests.exceptions.Timeout:
            self._log(f"Timeout connecting to {url}", level="error")
            return None
        except requests.exceptions.ConnectionError as e:
             # Log only distinct connection errors
             self._log(f"Connection error for {url}: {e}", level="error")
             return None
        except requests.exceptions.RequestException as e:
            self._log(f"Request error for {url}: {e}", level="error")
            if hasattr(e, 'response'): return e.response # Return error response if available
            return None

    # --- Check Methods ---

    def check_security_headers(self, response):
        """Analyzes security headers from a requests.Response object."""
        if not response:
            self._log("Cannot check headers, no response object provided.", level="error")
            return

        self._log(f"Analyzing headers for {response.url} (Status: {response.status_code})", level="progress")
        headers = response.headers # Case-insensitive dict-like object
        findings = []

        # Helper for explanations
        def add_finding(name, status, detail="", explanation="", level="info"):
            msg = f"    {name}: {status}"
            if detail: msg += f" ({detail})"
            # Prepend marker based on level
            marker = ""
            if level == "vuln": marker = "[!] "
            elif level == "warn": marker = "[?] "
            elif level == "info": marker = "[+] "

            findings.append(f"{marker}{msg}")
            if explanation: findings.append(f"        └── Why: {explanation}")

        # 1. Strict-Transport-Security (HSTS)
        hsts = headers.get('Strict-Transport-Security')
        if hsts:
            max_age = 0
            match = re.search(r'max-age=(\d+)', hsts, re.I)
            if match: max_age = int(match.group(1))

            includes_subdomains = 'includeSubDomains' in hsts
            preload = 'preload' in hsts

            detail = f"max-age={max_age}"
            if includes_subdomains: detail += "; includeSubDomains"
            if preload: detail += "; preload"

            if max_age >= 31536000: # Good practice: >= 1 year
                add_finding("Strict-Transport-Security", "Present (Strong)", detail, level="info")
            elif max_age > 0:
                add_finding("Strict-Transport-Security", "Present (Weak max-age)", detail, level="warn", explanation="max-age should ideally be >= 31536000 (1 year).")
            else:
                 add_finding("Strict-Transport-Security", "Present (max-age missing or 0)", detail, level="warn", explanation="HSTS header requires a positive max-age directive.")
        elif self.parsed_url.scheme == 'https': # Only relevant for HTTPS sites
            add_finding("Strict-Transport-Security", "Missing", level="warn", explanation="HSTS enforces HTTPS connections, reducing risk of downgrade attacks.")
        else:
             add_finding("Strict-Transport-Security", "N/A (Site is not HTTPS)", level="info")

        # 2. Content-Security-Policy (CSP)
        csp = headers.get('Content-Security-Policy')
        csp_report_only = headers.get('Content-Security-Policy-Report-Only')
        if csp:
            detail = f"Value: {csp[:100]}{'...' if len(csp)>100 else ''}"
            # Basic checks for common weaknesses (can be expanded significantly)
            weak = False
            explanation = ""
            if "'unsafe-inline'" in csp and ("script-src" in csp or "default-src" in csp):
                weak = True; explanation += " Allows inline scripts ('unsafe-inline'). "
            if "'unsafe-eval'" in csp and ("script-src" in csp or "default-src" in csp):
                weak = True; explanation += " Allows eval ('unsafe-eval'). "
            # Check for overly broad sources like '*' or 'https:' in critical directives
            # This requires more parsing... simplified check for now
            if "script-src *" in csp or "default-src *" in csp:
                weak = True; explanation += " Allows scripts from any source (*)."

            if weak:
                 add_finding("Content-Security-Policy", "Present (Potentially Weak)", detail, level="warn", explanation=explanation.strip())
            else:
                 add_finding("Content-Security-Policy", "Present", detail, level="info")
        elif csp_report_only:
            detail = f"Value: {csp_report_only[:100]}{'...' if len(csp_report_only)>100 else ''}"
            add_finding("Content-Security-Policy-Report-Only", "Present", detail, level="info", explanation="CSP is in report-only mode, not enforcing policy yet.")
        else:
            add_finding("Content-Security-Policy", "Missing", level="warn", explanation="CSP helps prevent XSS and other injection attacks.")

        # 3. X-Frame-Options
        xfo = headers.get('X-Frame-Options')
        if xfo:
             xfo_val = xfo.strip().upper()
             if xfo_val in ('DENY', 'SAMEORIGIN'):
                 add_finding("X-Frame-Options", "Present (Secure)", f"Value: {xfo_val}", level="info")
             elif xfo_val.startswith('ALLOW-FROM'):
                 add_finding("X-Frame-Options", "Present (ALLOW-FROM - Obsolete)", f"Value: {xfo}", level="warn", explanation="ALLOW-FROM is obsolete and may not work in modern browsers. Use CSP frame-ancestors instead.")
             else:
                  add_finding("X-Frame-Options", "Present (Unknown Value)", f"Value: {xfo}", level="warn")
        else:
             add_finding("X-Frame-Options", "Missing", level="warn", explanation="Prevents clickjacking by controlling frame embedding. Use DENY or SAMEORIGIN, or CSP frame-ancestors.")

        # 4. X-Content-Type-Options
        xcto = headers.get('X-Content-Type-Options')
        if xcto and xcto.strip().lower() == 'nosniff':
            add_finding("X-Content-Type-Options", "Present (nosniff)", level="info", explanation="Prevents browsers from MIME-sniffing response away from declared Content-Type.")
        elif xcto:
             add_finding("X-Content-Type-Options", "Present (Incorrect Value)", f"Value: {xcto}", level="warn", explanation="Should be set to 'nosniff'.")
        else:
             add_finding("X-Content-Type-Options", "Missing", level="warn", explanation="Should be set to 'nosniff' to prevent MIME-sniffing attacks.")

        # 5. Referrer-Policy
        refpol = headers.get('Referrer-Policy')
        common_policies = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url']
        if refpol:
            if refpol.strip().lower() in common_policies:
                 add_finding("Referrer-Policy", "Present", f"Value: {refpol}", level="info")
            else:
                 add_finding("Referrer-Policy", "Present (Unknown Value)", f"Value: {refpol}", level="warn")
        else:
            add_finding("Referrer-Policy", "Missing", level="info", explanation="Controls how much referrer information is sent with requests. Consider setting a policy like 'strict-origin-when-cross-origin'.")

        # 6. Permissions-Policy / Feature-Policy
        pp = headers.get('Permissions-Policy') or headers.get('Feature-Policy')
        if pp:
            add_finding("Permissions-Policy", "Present", f"Value: {pp[:100]}{'...' if len(pp)>100 else ''}", level="info", explanation="Controls which browser features (camera, microphone, etc.) can be used.")
        else:
            add_finding("Permissions-Policy", "Missing", level="info", explanation="Consider defining a Permissions-Policy to restrict unnecessary browser feature access.")

        # 7. Server Information Disclosure
        server = headers.get('Server')
        xpb = headers.get('X-Powered-By')
        xasp = headers.get('X-AspNet-Version') # Common ASP.NET disclosure

        details = []
        if server: details.append(f"Server: {server}")
        if xpb: details.append(f"X-Powered-By: {xpb}")
        if xasp: details.append(f"X-AspNet-Version: {xasp}")

        if details:
             add_finding("Server Info Disclosure", "Potentially Revealed", "; ".join(details), level="warn", explanation="Headers reveal server/technology details, potentially aiding attackers.")
        else:
             add_finding("Server Info Disclosure", "Not Obvious", level="info", explanation="Server/technology headers appear removed or generic (good practice).")

        # 8. Basic WAF / CDN Detection Headers
        cdn_waf_headers = {
            'Server': [('cloudflare', 'Cloudflare'), ('AkamaiGHost', 'Akamai'), ('ECS', 'Akamai'), ('ECAcc', 'Akamai'), ('Incapsula', 'Incapsula'), ('Sucuri/Cloudproxy', 'Sucuri'), ('awselb', 'AWS ELB'), ('Azura', 'Azure?'), ('GSE', 'Google')], # Check server header value patterns
            'X-CDN': [('.*', 'Generic CDN Header')], # Presence check
            'X-Sucuri-ID': [('.*', 'Sucuri WAF')],
            'X-Proxy-ID': [('.*', 'Incapsula WAF?')],
            'X-Iinfo': [('.*', 'Incapsula WAF?')],
            'X-Cache': [('.*', 'Potential Proxy/CDN Cache')],
            'Via': [('.*', 'Proxy Server Detected')],
            'Set-Cookie': [('^incap_ses_', 'Incapsula Cookie'), ('^visid_incap_', 'Incapsula Cookie'), ('^cf_clearance', 'Cloudflare Cookie'), ('AWSALB', 'AWS ELB Cookie')], # Check cookie name patterns
        }
        detected_fw = []
        for header_name, patterns in cdn_waf_headers.items():
            header_value = headers.get(header_name)
            if header_value:
                 for pattern, fw_name in patterns:
                      if header_name == 'Set-Cookie': # Special handling for Set-Cookie which can appear multiple times
                           # Need original response obj to get all Set-Cookie headers
                           cookies = response.raw.headers.getlist('Set-Cookie') # Use raw to get list
                           for cookie_str in cookies:
                                if re.search(pattern, cookie_str):
                                     if fw_name not in detected_fw: detected_fw.append(fw_name)
                      elif re.search(pattern, header_value, re.I):
                          if fw_name not in detected_fw: detected_fw.append(fw_name)

        if detected_fw:
            add_finding("Firewall / CDN Detected", ", ".join(detected_fw), level="info", explanation="Headers suggest the presence of a WAF, CDN, or proxy.")
        else:
            add_finding("Firewall / CDN Detected", "Not Obvious from common headers", level="info")

        self.results.extend(findings)


    def check_cookies(self, response):
        """Analyzes Set-Cookie headers from a requests.Response object."""
        if not response:
            self._log("Cannot check cookies, no response object provided.", level="error")
            return

        self._log(f"Analyzing cookies for {response.url}", level="progress")
        # Use response.raw.headers.getlist to handle multiple Set-Cookie headers
        cookie_headers = response.raw.headers.getlist('Set-Cookie')
        findings = []

        if not cookie_headers:
            findings.append("    No cookies set.")
        else:
            findings.append(f"    Found {len(cookie_headers)} Set-Cookie header(s):")
            for i, cookie_str in enumerate(cookie_headers):
                 findings.append(f"      Cookie #{i+1}: {cookie_str.split(';')[0]}") # Show name=value part

                 flags = []
                 if 'HttpOnly' in cookie_str: flags.append("HttpOnly")
                 if 'Secure' in cookie_str: flags.append("Secure")

                 samesite_match = re.search(r'SameSite=(Lax|Strict|None)', cookie_str, re.I)
                 samesite_policy = samesite_match.group(1) if samesite_match else "Not Set"
                 flags.append(f"SameSite={samesite_policy}")

                 findings.append(f"        Flags: {', '.join(flags)}")

                 # Security checks
                 if 'Secure' not in cookie_str and self.parsed_url.scheme == 'https':
                     findings.append("        [!] Warning: Cookie missing 'Secure' flag on HTTPS site.")
                     self._log("Cookie missing Secure flag on HTTPS.", level="warn")
                 if 'HttpOnly' not in cookie_str:
                     findings.append("        [?] Info: Cookie missing 'HttpOnly' flag (increases risk if XSS occurs).")
                 if samesite_policy == "None" and 'Secure' not in cookie_str:
                     findings.append("        [!] Warning: Cookie has 'SameSite=None' but missing 'Secure' flag (will be rejected by modern browsers).")
                 elif samesite_policy == "Not Set":
                      findings.append("        [?] Info: Cookie missing 'SameSite' attribute (defaults to Lax in modern browsers, but explicit is better).")

        self.results.extend(findings)


    def check_security_txt(self):
        """Checks for the presence of security.txt."""
        paths_to_check = ["/.well-known/security.txt", "/security.txt"]
        findings = []
        found = False
        for path in paths_to_check:
            sec_txt_url = urljoin(self.target_url, path)
            self._log(f"Checking for security.txt at {sec_txt_url}", level="progress")
            response = self._make_request(sec_txt_url, allow_redirects=False) # Don't follow redirects

            if response and response.status_code == 200:
                 content_type = response.headers.get('Content-Type', '').lower()
                 if 'text/plain' in content_type:
                     self._log(f"security.txt found at {sec_txt_url} with correct Content-Type.", level="info")
                     findings.append(f"    [+] Found at {sec_txt_url} (Status: 200, Content-Type: {content_type})")
                     # Optionally display content summary
                     content_summary = response.text.splitlines()[:10]
                     if len(response.text.splitlines()) > 10: content_summary.append("    ... (content truncated)")
                     findings.extend([f"        {line}" for line in content_summary])
                     found = True
                     break # Stop checking paths once found correctly
                 else:
                     self._log(f"File found at {sec_txt_url}, but Content-Type is not text/plain ('{content_type}').", level="warn")
                     findings.append(f"    [?] Found at {sec_txt_url} (Status: 200), but incorrect Content-Type: {content_type}")
                     # Don't mark as 'found=True' if content-type is wrong
            # Don't report 404s explicitly unless none are found at all

        if not found and not findings: # No 200 response on any path, and no warnings logged
            findings.append("    Not found at standard locations.")
            self._log("security.txt not found at standard locations.", level="info")

        self.results.extend(findings)


    def check_redirect_chain(self):
        """Follows redirects from the target URL and reports the chain."""
        self._log(f"Checking redirect chain for {self.target_url}", level="progress")
        chain = []
        current_url = self.target_url
        max_redirects = 10
        headers_to_send = {"User-Agent": self.session.headers["User-Agent"]} # Use consistent UA

        try:
            for i in range(max_redirects):
                 response = self._make_request(current_url, method="head", allow_redirects=False, headers=headers_to_send) # Use HEAD for efficiency

                 if response is None: # Request failed
                     chain.append(f"    -> Error reaching {current_url}")
                     break

                 status_code = response.status_code
                 chain.append(f"    -> {current_url} ({status_code})")

                 if 300 <= status_code <= 399: # Is redirect?
                     location = response.headers.get('Location')
                     if not location:
                         chain.append(f"    [! Error] Redirect status code but no Location header!")
                         break
                     # Resolve relative redirects
                     next_url = urljoin(current_url, location)
                     if next_url == current_url: # Avoid infinite loop on self-redirect
                          chain.append(f"    [! Error] Redirect loop detected to same URL.")
                          break
                     current_url = next_url
                 else: # Not a redirect, chain ends here
                     break
            else: # Loop finished without break (max redirects reached)
                 chain.append(f"    [! Warning] Maximum redirects ({max_redirects}) reached.")

        except Exception as e:
            self._log(f"Error during redirect check: {e}", level="error")
            chain.append(f"    [! Error] Exception during redirect check: {e}")

        self.results.extend(chain)

    def check_dns_records(self):
        """Performs DNS lookups for various record types."""
        if not self.hostname:
            self.results.append("    Invalid domain for DNS lookup.")
            return
        self._log(f"Performing extended DNS lookup for {self.hostname}", level="progress")

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'] # Added SOA, CAA
        dns_results = {}

        for r_type in record_types:
            try:
                self._log(f"Querying {r_type} records...", level="progress")
                # Use a slightly longer timeout for DNS? Default is often short.
                answers = dns.resolver.resolve(self.hostname, r_type, lifetime=self.request_timeout * 0.5) # Use half request timeout

                if r_type == 'MX':
                    dns_results[r_type] = sorted([f"{r.preference} {r.exchange.to_text()}" for r in answers])
                elif r_type == 'TXT':
                    dns_results[r_type] = ["\"" + " ".join(s.decode('utf-8', 'ignore') for s in rdata.strings) + "\"" for rdata in answers]
                elif r_type == 'SOA':
                     # SOA record has multiple fields (mname, rname, serial, refresh, retry, expire, minimum)
                     # Just display the first one's basic info for summary
                     r = answers[0]
                     dns_results[r_type] = [f"MNAME:{r.mname}, RNAME:{r.rname}, Serial:{r.serial}"]
                elif r_type == 'CAA':
                     # CAA format: flags issuer critical_value
                     dns_results[r_type] = [f"{r.flags} {r.tag.decode()} \"{r.value.decode()}\"" for r in answers]
                else: # A, AAAA, NS, CNAME
                    dns_results[r_type] = sorted([r.to_text() for r in answers])
                self._log(f"Found {len(dns_results[r_type])} {r_type} records.", level="info")
            except dns.resolver.NoAnswer:
                dns_results[r_type] = []
                self._log(f"No {r_type} records found.", level="info")
            except dns.resolver.NXDOMAIN:
                self._log(f"Domain {self.hostname} does not exist (NXDOMAIN). Aborting further DNS lookups.", level="error")
                dns_results = {"Error": "NXDOMAIN"} # Signal error
                break
            except dns.exception.Timeout:
                dns_results[r_type] = ["Query Timed Out"]
                self._log(f"{r_type} record query timed out.", level="warn")
            except Exception as e:
                dns_results[r_type] = [f"Error: {type(e).__name__}"]
                self._log(f"Error querying {r_type} records: {e}", level="error")

        # Format results
        if dns_results.get("Error"):
             self.results.append(f"    Error: {dns_results['Error']}")
        else:
             for record_type, values_list in dns_results.items():
                 if values_list:
                     self.results.append(f"    {record_type}:")
                     for val in values_list:
                         self.results.append(f"        {val}")
                 else:
                     self.results.append(f"    {record_type}: None found")

    # --- Main Scan Orchestration ---

    def run_all_checks(self):
        """Runs all implemented security checks."""
        self.results = [] # Clear previous results for this run
        self._log(f"Starting security checks for {self.target_url}", level="info")

        # Initial Request (needed for headers, cookies)
        # Follow redirects here to analyze the final landing page's headers/cookies
        self._log("Fetching initial page...", level="progress")
        initial_response = self._make_request(self.target_url, allow_redirects=True)

        # --- Section: HTTP Headers ---
        self.results.append("\n--- Security Headers ---")
        if initial_response:
             self.check_security_headers(initial_response)
        else:
             self.results.append("    Could not fetch URL to check headers.")

        # --- Section: Cookies ---
        self.results.append("\n--- Cookies ---")
        if initial_response:
             self.check_cookies(initial_response)
        else:
             self.results.append("    Could not fetch URL to check cookies.")

        # --- Section: File Checks ---
        self.results.append("\n--- Common Security Files ---")
        self.check_security_txt()

        # --- Section: Redirects ---
        self.results.append("\n--- Redirect Chain ---")
        self.check_redirect_chain()

        # --- Section: DNS ---
        self.results.append("\n--- DNS Records ---")
        self.check_dns_records()

        # --- Add more check sections here ---
        # e.g., Tech Stack, Whois (if moved from basic_info), etc.


        self._log("Security checks finished.", level="info")

        # Return combined results
        if not self.results:
            return "No security check results generated (check logs for errors)."
        else:
             # Filter out potential None entries if any check appends None erroneously
             final_results = [str(item) for item in self.results if item is not None]
             return "\n".join(final_results)


# --- Standalone function for main.py compatibility ---
# Ensure this exists if main.py calls it directly
def check_security_headers(target_url, progress_callback=None):
     """Standalone wrapper for basic header checks (can be expanded)."""
     scanner = SecurityChecksScanner(target_url, progress_callback=progress_callback)
     # For just headers, we need to make the request first
     response = scanner._make_request(target_url, allow_redirects=True)
     scanner.results = [] # Clear results specific to this call
     scanner.results.append("\n--- Security Headers ---")
     if response:
         scanner.check_security_headers(response)
     else:
         scanner.results.append("    Could not fetch URL to check headers.")
     return "\n".join(scanner.results)

# --- Example usage block ---
if __name__ == '__main__':
    # target = "https://github.com"
    # target = "https://expired.badssl.com/" # For HSTS tests on HTTPS
    # target = "http://httpbin.org/redirect/3" # For redirect tests
    target = "https://google.com"

    print(f"--- Testing SecurityChecksScanner on {target} ---")
    def simple_callback_for_test(message):
        print(f"UI_CALLBACK: {message}")

    scanner = SecurityChecksScanner(target, progress_callback=simple_callback_for_test)
    results = scanner.run_all_checks()

    print("\n--- Scan Results ---")
    print(results)


# --- END OF REVISED scanner/security_checks.py ---