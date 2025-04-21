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
from scanner.basic_info import BasicInfoScanner
from scanner.live_monitor import LiveMonitor
from utils.websocket_listener import WebSocketListener


from PyQt6.QtWidgets import *
from PyQt6 import uic
from PyQt6.QtCore import QThread, pyqtSignal
from omengui import Ui_MainWindow
import asyncio
import json
import websockets
from PyQt6.QtCore import QMetaObject, Qt, Q_ARG
from PyQt6.QtGui import QIcon

class OpenRedirectWorker(QThread):
    result_ready = pyqtSignal(str)

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url

    def run(self):
        scanner = OpenRedirectScanner(self.target_url)
        result = scanner.threaded_scan()
        self.result_ready.emit(f"[Open Redirect] {result}")


class SequentialScanThread(QThread):
    update_signal = pyqtSignal(str)

    def __init__(self, url, ui):
        super().__init__()
        self.url = url
        self.ui = ui

    def run(self):
        if self.ui.SQLcheck.isChecked():
            self.update_signal.emit("[+] Starting SQL Injection Scan...")
            result = SQLInjectionScanner(self.url).scan()
            self.update_signal.emit(result)
            self.update_signal.emit("[+] SQL Injection Scan Finished.\n")

        if self.ui.XSScheck.isChecked():
            self.update_signal.emit("[+] Starting XSS Scan...")
            result = XSSScanner(self.url).scan_xss()
            self.update_signal.emit(result)
            self.update_signal.emit("[+] XSS Scan Finished.\n")

        if self.ui.OpenRedirectcheck.isChecked():
            self.update_signal.emit("[+] Starting Open Redirect Scan...")
            result = OpenRedirectScanner(self.url).threaded_scan()
            self.update_signal.emit(result)
            self.update_signal.emit("[+] Open Redirect Scan Finished.\n")

        if self.ui.SSLcheck.isChecked():
            self.update_signal.emit("[+] Starting SSL Security Scan...")
            result = scan_ssl(self.url)
            self.update_signal.emit(result)
            self.update_signal.emit("[+] SSL Scan Finished.\n")

        if self.ui.SecurityHeadcheck.isChecked():
            self.update_signal.emit("[+] Starting Security Header Checks...")
            result = check_security_headers(self.url)
            self.update_signal.emit("\n".join(result))
            self.update_signal.emit("[+] Security Header Checks Finished.\n")

        self.update_signal.emit("[+] All selected scans completed.")

class OmenSightGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui=Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("OmenSight")
        self.setWindowIcon(QIcon("static/AdobeStock_1380649135_Preview.png"))
        self.ui.ScanButton.clicked.connect(self.run_scan)
        self.ui.LiveButton.clicked.connect(self.run_live_monitoring)
        self.ui.StopButton.clicked.connect(self.stop_live_monitoring)


    def run_scan(self):
        target_url = self.ui.URLinput.text().strip()
        if not target_url.startswith(("http://", "https://")):
            self.ui.textEdit.setPlainText("[-] Invalid URL. Please include the protocol (http:// or https://)")
            return
        self.ui.textEdit.clear()
        basic_info = BasicInfoScanner(target_url)
        basic_info_result = basic_info.scan()
        self.ui.textEdit.append(f"[+] Basic Information:\n{basic_info_result}\n")
        self.ui.textEdit.append(f"[+] Starting scan for: {target_url}\n")

        self.scan_thread = SequentialScanThread(target_url, self.ui)
        self.scan_thread.update_signal.connect(self.ui.textEdit.append)
        self.scan_thread.start()

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
        # thread_ws = threading.Thread(target=self.receive_messages, daemon=True)
        # thread_ws.daemon = True
        # thread_ws.start()
        thread_mitm = threading.Thread(target=start_mitmproxy)
        thread_mitm.daemon = True
        thread_mitm.start()

        self.websocket_listener = WebSocketListener()
        self.websocket_listener.message_received.connect(self.ui.textEdit.append)
        self.websocket_listener.start()

    # def receive_messages(self,*args):
    #         async def listen():
    #             try:
    #                 async with websockets.connect("ws://localhost:8765") as websocket:
    #                     while True:
    #                         message = await websocket.recv()
    #                         data =json.loads(message)
    #                         print(f"[+] Received message: {data['message']}")
    #                         QMetaObject.invokeMethod(
    #                     self.ui.textEdit,
    #                     "append",
    #                     Qt.ConnectionType.QueuedConnection,
    #                     Q_ARG(str, data["message"]))
    #             except (ConnectionRefusedError,websockets.exceptions.ConnectionClosedError):
    #                 print("[!] WebSocket connection failed. Retrying in 3 seconds...")
    #             time.sleep(3)
    #         loop =asyncio.new_event_loop()
    #         asyncio.set_event_loop(loop)
    #         loop.run_until_complete(listen())

    def stop_live_monitoring(self):
        async def send_stop_command():
            async with websockets.connect("ws://localhost:8765") as websocket:
                await websocket.send(json.dumps({"command":"stop"}))
        asyncio.run(send_stop_command())
        self.ui.textEdit.append("\n[+] Live monitoring stopped.")
        if self.websocket_listener:
            self.websocket_listener.stop()
            self.websocket_listener = None

        self.ui.textEdit.append("\n[+] Live monitoring stopped.")
if __name__ == "__main__":
         app=QApplication(sys.argv)
         window=OmenSightGUI()
         window.show()
         sys.exit(app.exec())