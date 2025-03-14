import requests
from bs4 import BeautifulSoup
import sys
import re
import os
from mitmproxy import http
from urllib.parse import urljoin


class SQLInjectionScanner:
    def __init__(self,target_url):
        """Initialize the SQL Injection scanner"""
        self.target_url=target_url
        self.user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
        self.session = requests.Session()

        self.session.headers["User-Agent"] = self.user_agent

        self.signatures = [
            r"you have an error in your sql syntax",  # MySQL
            r"unclosed quotation mark after the character string",  # SQL Server
            r"syntax error at or near",  # PostgreSQL
            r"ORA-\d{5}",  # Oracle Database
            r"Microsoft OLE DB Provider for ODBC Drivers",  # MS Access
        ]
        self.live_sqli_patterns = [
            r"union\s+select",
            r"or\s+\d+=\d+",
            r"'--",
            r"sleep\(\d+\)",
        ]
    def scan(self):
        """perform SQL Injection scanning on the target URL"""
        print(f"\n[+] Scanning {self.target_url} for SQL Injection")
        test_payload = "' OR 1=1--"
        headers = {"User-Agent": self.user_agent}
        url_sqli_result=None
        try:
            response=requests.get(self.target_url+test_payload,headers=headers,timeout=5)
            for pattern in self.signatures:
                if re.search(pattern,response.text, re.IGNORECASE):
                    url_sqli_result= f"Potential SQL Injection found at {self.target_url}"

        except requests.exceptions.RequestException as e:
            return f"Error: Could not connect to {self.target_url} - {str(e)}"
        form_sqli_result=self.scan_forms()

        return f"{url_sqli_result}\n{form_sqli_result}" if url_sqli_result or form_sqli_result else "No SQL Injection found"

    def scan_forms(self):
        """Scan forms on the target URL for SQL Injection"""
        forms=self.get_forms()
        if not forms:
            return "No forms found on the page"
        print(f"[+] Found {len(forms)} forms on {self.target_url}. Testing for vulnerabilities...")
        for form in forms:
            form_info=self.form_details(form)
            for i in ["'",'"']:
                data={input_tag["name"]:(input_tag["value"]+i if input_tag["type"]=="hidden" or input_tag["value"] else f"test{i}") for input_tag in form_info["inputs"] if input_tag["name"]}
                target_url=urljoin(self.target_url,form_info["action"])
                try:
                    if form_info["method"]=="post":
                        res=self.session.post(target_url,data=data)
                    else:
                        res=self.target.get(target_url,params=data)
                    if self.vulnerable(res):
                        return f"SQL Injection vulnerability found in {self.target_url} with {data}"
                except requests.exceptions.RequestException:
                    continue
        return "No SQL Injection vulnerabilities found in forms"

    def get_forms(self):
        try:
            response=self.session.get(self.target_url,timeout=5)
            soup=BeautifulSoup(response.content,"html.parser")
            return soup.find_all("form")
        except requests.exceptions.RequestException:
            return[]
    def form_details(self,form):
        """Extract form details"""
        details={}
        details["action"]=form.attrs.get("action","")
        details["method"]=form.attrs.get("method","get").lower()
        details["inputs"]=[
            {
                "type":input_tag.attrs.get("type","text"),
                "name":input_tag.attrs.get("name",""),
                "value": input_tag.attrs.get("value", "")
            } for input_tag in form.find_all("input")
            ]
        return details

    def vulnerable(self,response):
        """check if the response is vulnerable to SQL Injection"""
        for pattern in self.signatures:
            if re.search(pattern,response.text,re.IGNORECASE):
                return True
        return False

# def start():
#      """Hook mitproxy to monitor live traffic."""
#      target_url=input("[+] Enter the target website URL:").strip()
#      scanner=SQLInjectionScanner(target_url)
#      print(scanner.scan())
#      start_live=input("\n Start live monitoring? (y/n): ").strip().lower()
#      if start_live=="y":
#         print("\n Live monitoring started. Press ctr+c to stop")
#         os.system(f"mitmproxy -s scanner/live_monitor.py --set target={target_url}")
