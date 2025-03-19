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
from scanner.security_checks import check_security_headers
from PyQt6.QtWidgets import *
from PyQt6 import uic
from omengui import Ui_MainWindow
import asyncio
import json
import websockets
from PyQt6.QtCore import QMetaObject, Qt, Q_ARG
class OmenSightGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui=Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.ScanButton.clicked.connect(self.run_scan)
        self.ui.LiveButton.clicked.connect(self.run_live_monitoring)
        self.ui.StopButton.clicked.connect(self.stop_live_monitoring)

    def run_scan(self):
        target_url=self.ui.URLinput.text().strip()
        if not target_url.startswith(("http://","https://")):
            self.ui.textEdit.setPlainText("[-] Invalid URL. Please include the protocol (http:// or https://)")
            return
        self.ui.textEdit.setPlainText(f"[+] Scanning the website: {target_url}")
        #running checked scanners
        if self.ui.SQLcheck.isChecked():
            sql_scanner=SQLInjectionScanner(target_url)
            sql_result=sql_scanner.scan()
            self.ui.textEdit.append(f"\n[+] SQL Injection Result:{sql_result}\n")
        if self.ui.XSScheck.isChecked():
            xss_scanner = XSSScanner(target_url)
            xss_result = xss_scanner.scan_xss()
            self.ui.textEdit.append(f"[XSS] {xss_result}\n")

        if self.ui.OpenRedirectcheck.isChecked():
            redirect_scanner = OpenRedirectScanner(target_url)
            redirect_result = redirect_scanner.scan()
            self.ui.textEdit.append(f"[Open Redirect] {redirect_result}\n")

        if self.ui.SSLcheck.isChecked():
            ssl_result = scan_ssl(target_url)
            self.ui.textEdit.append(f"[SSL Security] {ssl_result}\n")

        if self.ui.SecurityHeadcheck.isChecked():
            security_headers_result = check_security_headers(target_url)
            self.ui.textEdit.append(f"[Security Headers] {security_headers_result}\n")
        self.ui.textEdit.append("\n[+] Scanning completed")

    def run_live_monitoring(self):
        target_url=self.ui.URLinput.text().strip()
        if not target_url.startswith(("http://","https://")):
            self.ui.textEdit.setPlainText("[-] Invalid URL. Please include the protocol (http:// or https://)")
            return
        self.ui.textEdit.setPlainText(f"[+] Starting live monitoring for the website: {target_url}")

        def start_mitmproxy():
            subprocess.Popen(["mitmproxy", "--mode", "regular",
        "--set", "ssl_insecure=true",
        "-s", "scanner/live_monitor.py",
        "--set", f"target={target_url}"])
        thread_ws = threading.Thread(target=self.receive_messages, daemon=True)
        thread_ws.daemon = True
        thread_ws.start()
        thread_mitm = threading.Thread(target=start_mitmproxy)
        thread_mitm.daemon = True
        thread_mitm.start()

    def receive_messages(self,*args):
            async def listen():
                try:
                    async with websockets.connect("ws://localhost:8765") as websocket:
                        while True:
                            message = await websocket.recv()
                            data =json.loads(message)
                            print(f"[+] Received message: {data['message']}")
                            QMetaObject.invokeMethod(
                        self.ui.textEdit,
                        "append",
                        Qt.ConnectionType.QueuedConnection,
                        Q_ARG(str, data["message"]))
                except (ConnectionRefusedError,websockets.exceptions.ConnectionClosedError):
                    print("[!] WebSocket connection failed. Retrying in 3 seconds...")
                time.sleep(3)
            loop =asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(listen())

    def stop_live_monitoring(self):
        async def send_stop_command():
            async with websockets.connect("ws://localhost:8765") as websocket:
                await websocket.send(json.dumps({"command":"stop"}))
        asyncio.run(send_stop_command())
        self.ui.textEdit.append("\n[+] Live monitoring stopped.")
if __name__ == "__main__":
         app=QApplication(sys.argv)
         window=OmenSightGUI()
         window.show()
         sys.exit(app.exec())