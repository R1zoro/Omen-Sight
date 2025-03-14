import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanner.sql_injection import SQLInjectionScanner

class XSSScanner:
    def __init__(self, target_url):
        """Initializing Cross-Site Scripting Scanner"""
        self.target_url=target_url
        self.session=requests.Session()

        self.xss_payloads=[
             "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "'><script>alert(1)</script>",
        ]

    def scan_xss(self):
        """Perform Cross-Site Scripting scanning on the target URL"""
        print(f"\n[+] Scanning {self.target_url} and forms if presnt for Cross-Site Scripting")
        for payload in self.xss_payloads:
            test_url=f"{self.target_url}?input={payload}"
            response=self.session.get(test_url,timeout=5)
            if payload in response.text:
                return(f"found XSS at {self.target_url} with payload:{payload}")
            else:
                url_xss_result=f"No XSS found in {self.target_url}"
        form_xss_result=self.scan_forms_xss()
        return f"{url_xss_result}\n{form_xss_result}" if url_xss_result or form_xss_result else "No XSS found in URLs"

    def scan_forms_xss(self):
        """Perform Cross-Site Scripting scanning on the forms of the target URL"""
        # print(f"\n[+] Scanning forms in {self.target_url} for Cross-Site Scripting")
        sqli_scanner=SQLInjectionScanner(self.target_url)
        forms=sqli_scanner.get_forms()
        if not forms:
            return "No forms found in the URL"
            for form in forms:
                form_info=sqli_scanner.form_details(form)
                for payload in self.xss_payloads:
                    data={input_tag["name"]:payload for input_tag in form_info["inputs"] if input_tag["name"]}
                    target_url=urljoin(self.target_url,form_info["action"])
                    try:
                        if form_info["method"]=="post":
                            res=self.session.post(target_url,data=data)
                        else:
                            res=self.session.get(target_url,params=data)
                        if payload in res.text:
                            return(f"found XSS at {target_url} with payload:{payload}")
                    except requests.exceptions.RequestException:
                        continue
        return "No XSS found in forms"