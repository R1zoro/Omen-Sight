import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import concurrent.futures
import os
import time
import threading
from functools import partial
import warnings

try:
    from .sql_injection import SQLInjectionScanner
except ImportError:
    print("[!] Warning: Could not import SQLInjectionScanner relatively. Trying absolute import.")
    from scanner.sql_injection import SQLInjectionScanner
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class XSSScanner:
    def __init__(self, target_url, progress_callback=None):

        """Initializing Cross-Site Scripting Scanner"""
        self.target_url = target_url
        self.progress_callback = progress_callback
        self.num_threads = 20
        self.request_timeout = 10
        self.xss_payload_file = os.path.join("static", "xss_payload.txt")
        self.xss_tags_file = os.path.join("static", "xss_tags.txt")
        self.xss_events_file = os.path.join("static", "xss_events.txt")
        self.reflection_marker = "omnsgtXSStest"
        self.final_url, self.initial_response = self._get_final_url_and_response(target_url)
        if not self.final_url:
            print(f"[!] Failed to fetch initial URL: {target_url}. Aborting XSS scan.")
            if self.progress_callback:
                self.progress_callback(f"[!] XSS Error: Failed to fetch initial URL: {target_url}")
            self.parsed_url = urlparse(target_url)
            self.session = requests.Session()
            self.session.verify = False
        else:
             if self.final_url != target_url:
                  print(f"[+] Initial URL {target_url} redirected to {self.final_url}. Scanning final URL.")
             self.parsed_url = urlparse(self.final_url)
             self.session = requests.Session()
             self.session.headers.update({
                 "User-Agent": "OmenSight Scanner/1.0"
             })
             self.session.verify = False
        self.found_vulnerabilities = []
        self.vulnerabilities_lock = threading.Lock()
        self.tags = []
        self.events = []
        self.payloads_cache = None

    def _get_final_url_and_response(self, url):
        """Makes an initial request allowing redirects to find the final landing URL."""
        temp_session = requests.Session()
        temp_session.headers.update({"User-Agent": "OmenSight Scanner/1.0"})
        temp_session.verify = False
        try:
            response = temp_session.get(url, timeout=self.request_timeout, allow_redirects=True)
            response.raise_for_status()
            return response.url, response
        except requests.exceptions.RequestException as e:
            print(f"[!] Error during initial fetch of {url}: {e}")
            return None, None
        finally:
             temp_session.close()


    def _load_file_lines(self, filepath):
        """Loads lines from a file, stripping whitespace and skipping comments/empty lines."""
        lines = []
        if not os.path.exists(filepath):
            print(f"[!] Warning: File not found: {filepath}")
            if self.progress_callback:
                 self.progress_callback(f"[!] XSS Error: File not found: {filepath}")
            return lines
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith('#'):
                        lines.append(stripped_line)
            print(f"[+] Loaded {len(lines)} items from {filepath}")
            return lines
        except Exception as e:
            print(f"[!] Error loading file {filepath}: {e}")
            if self.progress_callback:
                 self.progress_callback(f"[!] XSS Error loading file {filepath}: {e}")
            return []

    def _send_request(self, url, method="get", data=None, headers=None):
        """Sends an HTTP request using the session. IMPORTANT: Disables redirects for testing."""
        try:
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)

            if method.lower() == "post":
                response = self.session.post(url, data=data, headers=req_headers,
                                             timeout=self.request_timeout, allow_redirects=False)
            else: # GET
                response = self.session.get(url, params=data, headers=req_headers,
                                            timeout=self.request_timeout, allow_redirects=False)
            return response
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            return None

    def _check_reflection(self, test_string, response):
        """Checks if a specific string is present (reflected) in the response body."""
        if response and response.text:
            return test_string.lower() in response.text.lower()
        return False

    def _add_vulnerability(self, location_type, location_target, param_name, payload, vuln_url):
        """Adds a found vulnerability to the list, preventing duplicates."""
        finding = (
            f"[{location_type}] Potential XSS found at {location_target} "
            f"in parameter/input '{param_name}' "
            f"with payload: {payload[:100]}{'...' if len(payload)>100 else ''} "
            f"(Triggered URL/Action: {vuln_url})"
        )
        with self.vulnerabilities_lock:
            if finding not in self.found_vulnerabilities:
                print(f"[!] {finding}")
                self.found_vulnerabilities.append(finding)
                if self.progress_callback:
                    self.progress_callback(finding)


    def _fuzz_single_param(self, location_type, location_target, base_url, method, param_name, base_data):
        """
        Performs the multi-stage fuzzing process for a single parameter identified
        as potentially vulnerable by the initial reflection check.
        """
        print(f"[+] Fuzzing {location_type} parameter: '{param_name}' at {location_target}")
        if self.progress_callback:
             self.progress_callback(f"[~] XSS: Fuzzing {location_type} parameter: '{param_name}' at {location_target}...")

        successful_tags = set()
        successful_events = set()
        test_value_base = f"{self.reflection_marker}_{param_name}"


        print(f"  [>] Stage 1: Testing {len(self.tags)} tags for reflection...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_tag = {}
            for tag in self.tags:
                test_payload = f"<{tag}>"
                data_copy = base_data.copy()
                data_copy[param_name] = f"{test_value_base}{test_payload}"
                future = executor.submit(self._send_request, base_url, method, data=data_copy)
                future_to_tag[future] = (tag, test_payload)
            for future in concurrent.futures.as_completed(future_to_tag):
                tag, test_payload = future_to_tag[future]
                try:
                    response = future.result()
                    if self._check_reflection(test_payload, response):
                        successful_tags.add(tag)
                except Exception as e:
                     pass
        if not successful_tags:
            print(f"  [-] No tags reflected for parameter '{param_name}'. Skipping further fuzzing.")
            return
        print(f"  [+] Found {len(successful_tags)} reflected tags for '{param_name}'.")

        print(f"  [>] Stage 2: Testing {len(self.events)} events on {len(successful_tags)} reflected tags...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_event = {}
            for tag in successful_tags:
                for event in self.events:
                    test_payload = f"<{tag} {event}={self.reflection_marker}>"
                    data_copy = base_data.copy()
                    data_copy[param_name] = f"{test_value_base}{test_payload}"
                    future = executor.submit(self._send_request, base_url, method, data=data_copy)
                    future_to_event[future] = (tag, event, test_payload)
            for future in concurrent.futures.as_completed(future_to_event):
                tag, event, test_payload = future_to_event[future]
                try:
                    response = future.result()
                    if self._check_reflection(test_payload, response) or self._check_reflection(f"{event}={self.reflection_marker}", response):
                         successful_events.add(f"{tag} {event}")
                except Exception as e:
                    pass
        if not successful_events:
            print(f"  [-] No tag/event combinations reflected for parameter '{param_name}'. Skipping payload check.")
            return
        print(f"  [+] Found {len(successful_events)} reflected tag/event combinations for '{param_name}'.")

        if self.payloads_cache is None:
             self.payloads_cache = self._load_file_lines(self.xss_payload_file)
        if not self.payloads_cache:
             print("  [-] No payloads loaded or cache empty. Cannot test payloads.")
             return

        relevant_payloads = []
        for payload in self.payloads_cache:
            payload_lower = payload.lower()
            for combo in successful_events:
                tag, event = combo.split(' ', 1)
                if payload_lower.startswith(f"<{tag}") and f" {event}" in payload_lower:
                    relevant_payloads.append(payload)
                    break
        if not relevant_payloads:
            print(f"  [-] No relevant payloads found based on reflected tags/events for '{param_name}'.")
            return

        print(f"  [>] Stage 3: Testing {len(relevant_payloads)} relevant payloads for '{param_name}'...")
        if self.progress_callback:
            self.progress_callback(f"[~] XSS ({param_name}): Testing {len(relevant_payloads)} relevant payloads...")

        # --- Payload Counter and Progress Reporting ---
        payload_counter = 0
        reporting_interval = 200

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_payload = {}
            for payload in relevant_payloads:
                data_copy = base_data.copy()
                data_copy[param_name] = payload
                final_url = base_url
                if method.lower() == 'get':
                   final_url += "?" + urlencode(data_copy, quote_via=quote)

                future = executor.submit(self._send_request, base_url, method, data=data_copy)
                future_to_payload[future] = (payload, final_url)


            for future in concurrent.futures.as_completed(future_to_payload):
                payload, final_url = future_to_payload[future]
                payload_counter += 1

                try:
                    response = future.result()
                    if self._check_reflection(payload, response):
                        self._add_vulnerability(location_type, location_target, param_name, payload, final_url)
                except Exception as e:
                    pass
                if payload_counter % reporting_interval == 0:
                    progress_msg = f"[~] XSS ({param_name}): Tested ~{payload_counter}/{len(relevant_payloads)} payloads..."
                    print(progress_msg)
                    if self.progress_callback:
                        self.progress_callback(progress_msg)

        print(f"  [+] Finished testing payloads for '{param_name}'.")


    def scan_xss(self):
        """Perform multi-stage XSS scanning on URL parameters and forms."""
        print(f"\n[+] Starting XSS Scan for {self.target_url}...")
        if self.progress_callback:
             self.progress_callback(f"[+] Starting XSS Scan for {self.target_url}...")
        if not self.final_url or not self.initial_response:
             message = "[!] XSS Scan Aborted: Could not fetch the target URL."
             print(message)
             if self.progress_callback:
                  self.progress_callback(message)
             return message

        self.found_vulnerabilities = []
        self.payloads_cache = None
        self.tags = self._load_file_lines(self.xss_tags_file)
        self.events = self._load_file_lines(self.xss_events_file)

        if not self.tags or not self.events:
            message = "[!] Cannot proceed with fuzzing: Tags or Events file missing/empty."
            print(message)
            if self.progress_callback:
                self.progress_callback(message)
        print(f"[+] Checking URL parameters in {self.final_url} for reflection...")
        base_url_path = self.parsed_url._replace(query="").geturl()
        original_params = parse_qs(self.parsed_url.query)
        vulnerable_url_params = []

        if original_params:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                future_to_param = {}
                for param_name, param_values in original_params.items():
                    if not param_values: continue
                    original_value = param_values[0]
                    test_payload = f"{original_value}{self.reflection_marker}"
                    data_copy = {k: v[0] for k, v in original_params.items() if v}
                    data_copy[param_name] = test_payload

                    future = executor.submit(self._send_request, base_url_path, "get", data=data_copy)
                    future_to_param[future] = param_name

                for future in concurrent.futures.as_completed(future_to_param):
                    param_name = future_to_param[future]
                    try:
                        response = future.result()
                        if self._check_reflection(self.reflection_marker, response):
                            print(f"  [!] Initial reflection detected in URL parameter: '{param_name}'")
                            vulnerable_url_params.append(param_name)
                    except Exception as e:

                         pass
        else:
             print("[-] No query parameters found in the final URL.")

        if vulnerable_url_params:
            base_data_get = {k: v[0] for k, v in original_params.items() if v}
            for param_name in vulnerable_url_params:
                self._fuzz_single_param("URL", self.final_url, base_url_path, "get", param_name, base_data_get)

        print(f"\n[+] Checking forms in {self.final_url} for reflection...")
        forms = []
        try:
            soup = BeautifulSoup(self.initial_response.content, "html.parser")
            forms = soup.find_all("form")
            form_finder = None
            if forms:
                 form_finder = SQLInjectionScanner(self.final_url)

        except Exception as e:
            print(f"[!] Error parsing forms from {self.final_url}: {e}")
            forms = []

        if not forms:
            print("[-] No forms found on the page.")
        else:
            print(f"[+] Found {len(forms)} forms. Performing initial reflection checks...")
            form_scan_jobs = []

            for form in forms:
                 try:
                     if not form_finder: continue
                     form_details = form_finder.form_details(form)
                     form_action = form_details.get("action", "")
                     form_target_url = urljoin(self.final_url, form_action)
                     form_method = form_details.get("method", "get").lower()
                     form_base_data = {}
                     inputs_to_test = []

                     for input_tag in form_details.get("inputs", []):
                          input_name = input_tag.get("name")
                          if input_name:
                              input_value = input_tag.get("value", "test")
                              form_base_data[input_name] = input_value
                              inputs_to_test.append(input_name)

                     for input_name in inputs_to_test:
                          data_copy = form_base_data.copy()
                          original_value = data_copy[input_name]
                          data_copy[input_name] = f"{original_value}{self.reflection_marker}"

                          response = self._send_request(form_target_url, form_method, data=data_copy)

                          if self._check_reflection(self.reflection_marker, response):
                              print(f"  [!] Initial reflection detected in FORM input: '{input_name}' (Action: {form_action}, Target: {form_target_url})")
                              form_scan_jobs.append((form_target_url, form_method, input_name, form_base_data.copy()))

                 except Exception as e:
                      print(f"[!] Error processing form (Action: {form.get('action', 'N/A')}): {e}")

            if form_scan_jobs:
                print(f"\n[+] Fuzzing {len(form_scan_jobs)} potentially vulnerable form inputs...")
                if self.progress_callback:
                     self.progress_callback(f"[~] XSS: Fuzzing {len(form_scan_jobs)} potentially vulnerable form inputs...")
                for form_target_url, form_method, input_name, base_data in form_scan_jobs:
                    self._fuzz_single_param("Form", form_target_url, form_target_url, form_method, input_name, base_data)
            else:
                 print("[-] No form inputs showed initial reflection.")


        # --- Final Report ---
        print("\n[+] XSS Scan Finished.")
        if not self.found_vulnerabilities:
            final_message = "No potential XSS vulnerabilities found by reflection."
            if self.progress_callback:
                self.progress_callback(final_message)
            return final_message
        else:
            results_header = "[!] Potential XSS Vulnerabilities Found:"
            return "\n".join([results_header] + self.found_vulnerabilities)

if __name__ == '__main__':
    target = "https://xss-game.appspot.com/level1"
    print(f"--- Testing XSS Scanner on {target} ---")
    def simple_print_callback(message):
        print(f"CALLBACK: {message}")

    scanner = XSSScanner(target, progress_callback=simple_print_callback)
    results = scanner.scan_xss()
    print("\n--- Scan Results ---")
    print(results)
 