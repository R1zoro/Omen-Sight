from mitmproxy import http
import re
import sys
import asyncio
import json
import websockets

class LiveMonitor:
    def __init__(self):
        """Initialize Live Monitoring for SQLi and XSS"""
        self.sqli_patterns = [
            r"union\s+select",
            r"or\s+\d+=\d+",
            r"'--",
            r"sleep\(\d+\)",
        ]
        self.xss_patterns = [
            r"<script>.*?</script>",
            r"javascript:",
            r"onerror=.*?",
        ]

    async def request(self, flow: http.HTTPFlow):
        """Intercept live HTTP requests and check for SQL Injection & XSS"""
        request_data = flow.request.text
        detected_issue = None

        for pattern in self.sqli_patterns:
            if re.search(pattern, request_data, re.IGNORECASE):
                detected_issue = f"⚠ Live SQL Injection detected: {flow.request.pretty_url}"

        for pattern in self.xss_patterns:
            if re.search(pattern, request_data, re.IGNORECASE):
                detected_issue = f"⚠ Live XSS detected: {flow.request.pretty_url}"

        message = detected_issue if detected_issue else f"[MONITORING] Request to: {flow.request.pretty_url}"

        asyncio.create_task(send_websocket_message(message))

async def send_websocket_message(message):
    """Send detection messages to the GUI via WebSocket"""
    async with websockets.connect("ws://localhost:8765") as websocket:
        await websocket.send(json.dumps({"message": message}))

async def websocket_server():
    """WebSocket server to communicate with the GUI"""
    async with websockets.serve(handle_client, "localhost", 8765):
        print("[+] WebSocket server started on ws://localhost:8765")
        await asyncio.Future()  # Keep running

async def handle_client(websocket, path):
    """Handle incoming messages from the GUI"""
    try:
        async for message in websocket:
            data = json.loads(message)
            if data.get("command") == "stop":
                print("[+] Stopping Live Monitoring...")
                await websocket.send(json.dumps({"message": "Live Monitoring Stopped"}))
                return  # Exit when stop command is received
    except websockets.exceptions.ConnectionClosed:
        print("[!] WebSocket connection closed.")

async def run_mitmproxy():
    """Start mitmproxy and WebSocket together"""
    print("[+] Starting mitmproxy with live monitoring...")
    loop = asyncio.get_running_loop()
    mitmproxy_task = loop.run_in_executor(None, lambda: sys.exit(os.system("mitmproxy -s scanner/live_monitor.py --set web_open_browser=false")))
    await mitmproxy_task

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.create_task(websocket_server())
    loop.create_task(run_mitmproxy())
    loop.run_forever()  #
