
import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re

from urllib.parse import urlsplit
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss import XSSScanner
from scanner.open_redirect import OpenRedirectScanner
from scanner.ssl_checker import scan_ssl
from scanner.security_checks import SecurityChecksScanner
from scanner.basic_info import BasicInfoScanner
from scanner.live_monitor import LiveMonitor
import signal

from PyQt6.QtWidgets import *
from PyQt6 import uic
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtCore import QTimer
from omengui import Ui_MainWindow

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
            sql_scanner = SQLInjectionScanner(self.url, progress_callback=self.update_signal.emit)
            result = sql_scanner.scan()
            self.update_signal.emit(result)
            self.update_signal.emit("[+] SQL Injection Scan Finished.\n")

        if self.ui.XSScheck.isChecked():
            self.update_signal.emit("[+] Starting XSS Scan...")
            xss_scanner = XSSScanner(self.url, progress_callback=self.update_signal.emit)
            result = xss_scanner.scan_xss()
            self.update_signal.emit(result)
            self.update_signal.emit("[+] XSS Scan Finished.\n")

        if self.ui.OpenRedirectcheck.isChecked():
            self.update_signal.emit("[+] Starting Open Redirect Scan...")
            or_scanner = OpenRedirectScanner(self.url, progress_callback=self.update_signal.emit)
            result = or_scanner.threaded_scan()
            self.update_signal.emit(result)
            self.update_signal.emit("[+] Open Redirect Scan Finished.\n")

        if self.ui.SSLcheck.isChecked():
            self.update_signal.emit("[+] Starting SSL Security Scan...")
            result = scan_ssl(self.url, progress_callback=self.update_signal.emit)
            self.update_signal.emit(result)
            self.update_signal.emit("[+] SSL Scan Finished.\n")

        if self.ui.SecurityHeadcheck.isChecked():
            self.update_signal.emit("[+] Starting Security Header Checks...")
            try:
                sec_scanner = SecurityChecksScanner(self.url, progress_callback=self.update_signal.emit)
                result = sec_scanner.run_all_checks()
                self.update_signal.emit(result)
            except ImportError as e:
                error_msg = f"[-] SecCheck Error: Failed to import required library: {e}. Please ensure dependencies are installed."
                print(error_msg)
                self.update_signal.emit(error_msg)
            except Exception as e:
                error_msg = f"[-] SecCheck Error: An unexpected error occurred: {e}"
                print(error_msg)
                self.update_signal.emit(error_msg)

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
        self.mitmweb_process = None
        self.ui.actionSave.triggered.connect(self.save_output_to_file_via_menu)


    def save_output_to_file_via_menu(self):
        content = self.ui.textEdit.toPlainText()
        if not content.strip():
            self.ui.textEdit.append("[!] No output to save.")
            return

        target_url_raw = self.ui.URLinput.text().strip()
        suggested_filename = "omensight_scan_results.txt"
        if target_url_raw:
            try:
                parsed_url = urlsplit(target_url_raw)

                hostname_sanitized = re.sub(r'[^\w.\-_]', '_', parsed_url.netloc)
                if not hostname_sanitized:
                    hostname_sanitized = "unknown_target"

                timestamp = time.strftime("%Y%m%d-%H%M%S")
                suggested_filename = f"omensight_{hostname_sanitized}_{timestamp}.txt"
            except Exception as e:
                print(f"Error generating suggested filename: {e}")


        filePath, _ = QFileDialog.getSaveFileName(
            self,
            "Save Scan Output",
            suggested_filename,
            "Text Files (*.txt);;Log Files (*.log);;All Files (*)"   
        )

        if filePath:
            try:
                with open(filePath, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.ui.textEdit.append(f"[+] Output saved successfully to: {filePath}")

            except Exception as e:
                error_msg = f"[-] Error saving output to {filePath}: {e}"
                self.ui.textEdit.append(error_msg)
                print(error_msg)
        else:
            self.ui.textEdit.append("[~] Save output operation cancelled by user.")

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

        if os.name != 'nt':
            self.ui.textEdit.append("[-] Live monitoring is currently configured for Windows only.")
            return

        self.ui.textEdit.setPlainText("[+] Starting live monitoring with mitmweb (Windows mode)...\n"
                                      "Please ensure your browser/system is configured to use mitmproxy (usually http://localhost:8080).\n"
                                      "Mitmweb interface will be available at http://localhost:8081.")

        command = [
            "mitmweb",
            "--set", "ssl_insecure=true",
            "-s", os.path.join("scanner", "live_monitor.py"),
            "--set", "web_open_browser=true",
            "--set", "web_host=127.0.0.1"
        ]

        try:
            if self.mitmweb_process and self.mitmweb_process.poll() is None:
                self.ui.textEdit.append("[!] An existing mitmweb process seems to be running. Please stop it first or check manually.")
                return

            self.mitmweb_process = subprocess.Popen(
                command,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            self.ui.textEdit.append("[+] Mitmweb process started (PID: {}).".format(self.mitmweb_process.pid))

        except FileNotFoundError:
            self.ui.textEdit.append("[-] Error: mitmweb command not found. Is mitmproxy installed and in your PATH?")
            self.mitmweb_process = None
        except Exception as e:
            self.ui.textEdit.append(f"[-] Error starting mitmweb: {e}")
            self.mitmweb_process = None


    def stop_live_monitoring(self):
        if os.name != 'nt':
            self.ui.textEdit.append("[-] Live monitoring stop is currently configured for Windows only.")

            if self.mitmweb_process:
                 self.mitmweb_process = None
                 self.ui.textEdit.append("[+] Mitmweb process reference cleared (non-Windows attempt).")
            return

        if self.mitmweb_process and self.mitmweb_process.poll() is None:
            pid = self.mitmweb_process.pid
            self.ui.textEdit.append(f"\n[+] Attempting to stop mitmweb process (PID: {pid}) on Windows...")
            try:
                self.mitmweb_process.send_signal(signal.CTRL_BREAK_EVENT)
                try:
                    self.mitmweb_process.wait(timeout=5)
                    self.ui.textEdit.append("[+] Mitmweb process signaled (CTRL_BREAK_EVENT) and exited.")
                except subprocess.TimeoutExpired:
                    self.ui.textEdit.append("[!] Mitmweb did not exit after CTRL_BREAK_EVENT. Trying terminate().")
                    self.mitmweb_process.terminate()
                    try:
                        self.mitmweb_process.wait(timeout=3)
                        self.ui.textEdit.append("[+] Mitmweb process terminated.")
                    except subprocess.TimeoutExpired:
                        self.ui.textEdit.append("[!] Mitmweb process did not terminate gracefully after terminate(), killing...")
                        self.mitmweb_process.kill()
                        self.mitmweb_process.wait(timeout=3)
                        self.ui.textEdit.append("[+] Mitmweb process killed.")
                except Exception as e_wait:
                     if self.mitmweb_process.poll() is not None:
                        self.ui.textEdit.append(f"[+] Mitmweb process exited after signal (wait reported: {e_wait}).")
                     else:
                        self.ui.textEdit.append(f"[!] Unknown state after signaling mitmweb: {e_wait}")


            except ProcessLookupError:
                self.ui.textEdit.append("[+] Mitmweb process was not found (likely already terminated).")
            except Exception as e:
                self.ui.textEdit.append(f"[!] Error stopping mitmweb: {e}")
            finally:
                self.mitmweb_process = None
        elif self.mitmweb_process and self.mitmweb_process.poll() is not None:
            self.ui.textEdit.append("\n[+] Mitmweb process was already stopped.")
            self.mitmweb_process = None
        else:
            self.ui.textEdit.append("\n[+] Mitmweb process not running or not tracked by the application.")

        self.ui.textEdit.append("Live monitoring stop sequence initiated.")

    def _log_to_gui(self, message, level="info"):
        self.ui.textEdit.append(message)


if __name__ == "__main__":
         app=QApplication(sys.argv)
         window=OmenSightGUI()
         window.show()
         sys.exit(app.exec())
