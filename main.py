import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss import XSSScanner
from scanner.open_redirect import OpenRedirectScanner
from scanner.ssl_checker import scan_ssl
from PyQT6.QTWidgets import*
from PyQT6 import uic


def main():
    print("\nOMEN SIGHT - Web Application Security Scanner")
    print("---------------------------------------------")
    #taking url input
    website=input("[+] Enter the target website URL:").strip()
    #checking if the url is valid
    if not website.startswith(("http://","https://")):
        print("[-] Invalid URL. Please include the protocol (http:// or https://)")
        return
    print(f"\n[+] Scanning the website: ",website)

    #static scanning for SQLi
    sql_scanner=SQLInjectionScanner(website)
    sqli_result=sql_scanner.scan()
    print("\n[+] SQL Injection Result:")
    print("-------------------------")
    print(f"SQL Injection: {sqli_result}")
    print("\n[+] Scanning completed")

    #static scanning for XSS
    xss_scanner=XSSScanner(website)
    xss_result=xss_scanner.scan_xss()
    print("\n[+] XSS Scanning Result:")
    print("-------------------------")
    print(f"XSS Attack: {xss_result}")
    print("\n[+] Scanning completed")
    #SSL scanning
    print("\n[+] SSL Scanning Result:")
    ssl_result=scan_ssl(website)
    print(ssl_result)
    #Open Redirect Scanning
    redirect_scanner=OpenRedirectScanner(website)
    redirect_result=redirect_scanner.scan()
    print(f"\n[+] Open Redirect Scanning Result: { redirect_result}")
    #live monitoring
    start_live=input("\n Start live monitoring? (y/n): ").strip().lower()
    if start_live=="y":
        print("\n Live monitoring started. Press ctr+c to stop")
        os.system(f"mitmproxy -s scanner/live_monitor.py --set target={website}")

if __name__ == "__main__":
         main()