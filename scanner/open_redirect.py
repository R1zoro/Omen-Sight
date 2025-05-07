# --- START OF REVISED scanner/open_redirect.py ---

import concurrent.futures
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote # Added more imports

class OpenRedirectScanner:
    def __init__(self, target_url, progress_callback=None, request_timeout=5): # Added callback and timeout
        self.target_url = target_url
        self.progress_callback = progress_callback
        self.request_timeout = request_timeout

        self.redirect_params = ["next", "url", "redirect", "return", "goto", "dest", "destination", "target", "continue", "path"] # Expanded list

        # Note: _log might not be fully available during __init__ if progress_callback isn't set yet.
        # load_payloads will print directly if it encounters issues during initialization.
        self.payloads = self._load_payloads_static("static/open_direct_payloads.txt") # Renamed for clarity

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "OmenSight Scanner/1.0"
        })
        self.session.verify = False # Allow scans on sites with self-signed certs
        if not self.session.verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _log(self, message, level="info"):
        """Helper for logging to console and GUI callback."""
        prefix_map = {"info": "[+]", "progress": "[~]", "vuln": "[!]", "warn": "[!]", "error": "[-]"}
        prefix = prefix_map.get(level, "[?]")
        full_message = f"{prefix} OpenRedirect: {message}"
        print(full_message)
        if self.progress_callback and level in ["progress", "vuln", "info", "warn", "error"]:
            self.progress_callback(full_message)

    def _load_payloads_static(self, file_path): # Renamed and using print for init-time errors
        """Loads payloads from a file, with fallback."""
        default_payloads = ["http://example.com", "//example.com", "https://example.org"] # Safer defaults
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                loaded_payloads = [line.strip() for line in f.readlines() if line.strip()]
                if loaded_payloads:
                    # Use self._log if available, otherwise print
                    log_func = getattr(self, '_log', print)
                    if log_func == print: # If _log not yet fully set up
                         print(f"[+] OpenRedirect: Loaded {len(loaded_payloads)} payloads from {file_path}")
                    else:
                         self._log(f"Loaded {len(loaded_payloads)} payloads from {file_path}", level="info")
                    return loaded_payloads
                else:
                    log_func = getattr(self, '_log', print)
                    if log_func == print:
                         print(f"[!] OpenRedirect: Payload file {file_path} is empty. Using default payloads.")
                    else:
                         self._log(f"Payload file {file_path} is empty. Using default payloads.", level="warn")
                    return default_payloads
        except FileNotFoundError:
            log_func = getattr(self, '_log', print)
            if log_func == print:
                print(f"[!] OpenRedirect: Payload file not found: {file_path}. Using default payloads.")
            else:
                self._log(f"Payload file not found: {file_path}. Using default payloads.", level="warn")
            return default_payloads
        except IOError as e:
            log_func = getattr(self, '_log', print)
            if log_func == print:
                print(f"[!] OpenRedirect: Error reading payload file {file_path}: {e}. Using default payloads.")
            else:
                self._log(f"Error reading payload file {file_path}: {e}. Using default payloads.", level="error")
            return default_payloads

    def _test_single_payload(self, original_target_url, param_to_test, payload_value, payload_type_desc):
        """
        Tests a single parameter with a single payload value for open redirect.
        Returns the vulnerable URL string if found, else None.
        """
        try:
            parsed_original_url = urlparse(original_target_url)
            query_params_dict = parse_qs(parsed_original_url.query)

            # Add/replace our test parameter; ensure its value is a list for urlencode
            query_params_dict[param_to_test] = [payload_value]

            # Rebuild the query string
            new_query_string = urlencode(query_params_dict, doseq=True)

            # Create the new URL parts, replacing the query
            test_url_parts = list(parsed_original_url) # Convert ParseResult to list to modify
            test_url_parts[4] = new_query_string      # Index 4 is 'query'
            test_url = urlunparse(test_url_parts)

            self._log(f"Testing {param_to_test} with {payload_type_desc} payload: {payload_value[:50]}... URL: {test_url[:100]}...", level="progress")

            response = self.session.get(test_url, allow_redirects=True, timeout=self.request_timeout)

            # The final URL after all redirects have been followed
            final_landed_url = response.url

            # Parse the original target URL's domain and the final landed URL's domain
            original_domain = urlparse(original_target_url).netloc.lower()
            final_domain = urlparse(final_landed_url).netloc.lower()

            # Check if the final domain is different from the original domain
            # And ensure the final domain is not empty (in case of weird redirects like to 'about:blank')
            if final_domain and final_domain != original_domain:
                # To be more precise, check if the payload is *part of* the final domain or path
                # This helps confirm our payload caused the off-site redirect
                # A simple check: is our payload (or a significant part of it) in the final URL?
                # This is a heuristic and might need refinement.
                # For evil.com, we check if 'evil.com' is in final_domain.
                # For //evil.com, we check if 'evil.com' is in final_domain.
                payload_check_part = urlparse(payload_value).netloc or payload_value # Get domain from payload or use raw
                if payload_check_part and (payload_check_part in final_domain or payload_check_part in final_landed_url):
                    vuln_string = f"Potential Open Redirect ({payload_type_desc}): {test_url} \n    ➜ Redirected to: {final_landed_url}"
                    self._log(f"Vulnerability found! {vuln_string}", level="vuln")
                    return vuln_string
            return None # No vulnerability detected for this specific payload/parameter
        except requests.exceptions.Timeout:
            self._log(f"Timeout testing {param_to_test}={payload_value[:50]}... on {original_target_url}", level="warn")
            return None
        except requests.exceptions.RequestException as e:
            self._log(f"Request error testing {param_to_test}={payload_value[:50]}... on {original_target_url}: {e}", level="error")
            return None
        except Exception as e: # Catch any other unexpected error during the test
            self._log(f"Unexpected error testing {param_to_test}={payload_value[:50]}...: {e}", level="error")
            return None


    def threaded_scan(self):
        """
        Scans the target_url for open redirect vulnerabilities using threads.
        Tests common redirect parameters with various payloads (raw and URL-encoded).
        """
        self._log(f"Starting Open Redirect scan for {self.target_url}...", level="info")
        detected_vulnerabilities = []

        # If target_url itself has no query string, we test by appending.
        # If it has a query string, _test_single_payload handles merging.
        # No special handling needed here for the base target_url structure itself.

        tasks_to_submit = []
        for param in self.redirect_params:
            for raw_payload in self.payloads:
                # Task for raw payload
                tasks_to_submit.append((self.target_url, param, raw_payload, "raw"))

                # Task for URL-encoded payload
                encoded_payload = quote(raw_payload)
                # Only test encoded if it's different from raw and not empty
                if encoded_payload and encoded_payload != raw_payload:
                    tasks_to_submit.append((self.target_url, param, encoded_payload, "URL-encoded"))

        if not tasks_to_submit:
            self._log("No payloads or parameters to test.", level="warn")
            return "No Open Redirect tests performed (no payloads/params)."

        self._log(f"Submitting {len(tasks_to_submit)} tests to thread pool...", level="progress")

        # Using max_workers=10, can be adjusted
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Submit jobs: executor.submit(function, *args)
            # The args in tasks_to_submit match _test_single_payload's signature after self
            future_to_task = {executor.submit(self._test_single_payload, *task_args): task_args for task_args in tasks_to_submit}

            for future in concurrent.futures.as_completed(future_to_task):
                task_args_done = future_to_task[future] # For logging context if needed
                try:
                    result_from_worker = future.result() # Get result from _test_single_payload
                    if result_from_worker:
                        detected_vulnerabilities.append(result_from_worker)
                except Exception as exc:
                    # Log exceptions from worker threads
                    param_done, payload_done = task_args_done[1], task_args_done[2]
                    self._log(f"Task for param '{param_done}' with payload '{payload_done[:50]}' generated an exception: {exc}", level="error")

        self._log(f"Open Redirect scan finished. Found {len(detected_vulnerabilities)} potential vulnerabilities.", level="info")
        if detected_vulnerabilities:
            # Join unique vulnerabilities
            unique_vulns = sorted(list(set(detected_vulnerabilities)))
            return "\n".join(unique_vulns)
        else:
            return "No Open Redirect vulnerabilities found."

# Example usage (if run directly)
if __name__ == '__main__':
    # Create a dummy payload file for testing if it doesn't exist
    import os
    if not os.path.exists("static"): os.makedirs("static")
    if not os.path.exists("static/open_direct_payloads.txt"):
        with open("static/open_direct_payloads.txt", "w") as f:
            f.write("http://example.com\n")
            f.write("//google.com/robots.txt\n") # Test //
            f.write("https://github.com\n")
            f.write("javascript:alert(1)//example.com\n") # Less likely for pure OR, more XSS-ish

    # Example: Test against a known vulnerable local app or a test site
    # target_site = "http://localhost:8000/redirect_test?someparam=value"
    # target_site = "http://testphp.vulnweb.com/" # This site might not have OR easily
    target_site = "https://httpbin.org/redirect-to?url=http://example.com" # Test with httpbin
    # target_site = "https://httpbin.org/get" # A page without OR params

    print(f"--- Testing OpenRedirectScanner on {target_site} ---")

    def simple_callback(message):
        print(f"UI_CALLBACK: {message}")

    scanner = OpenRedirectScanner(target_site, progress_callback=simple_callback, request_timeout=7)
    results = scanner.threaded_scan()

    print("\n--- Scan Results ---")
    print(results)

# --- END OF REVISED scanner/open_redirect.py ---