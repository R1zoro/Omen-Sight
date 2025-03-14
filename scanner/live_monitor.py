from mitmproxy import http
import re
import sys
class LiveMonitor:
    def __init__(self,):
        """Initialize live SQL Injection monitor with a target URL."""

        self.sqli_patterns = [
            r"union\s+select",
            r"or\s+\d+=\d+",
            r"'--",
            r"sleep\(\d+\)",
        ]
        self.xss_patterns = [
            r"<script>.?</script>",
            r"javascript:",
            r"onerror=.*?",]

    def request(self, flow: http.HTTPFlow):
        """Intercept live HTTP requests and check for SQL Injection."""
        target_url=ctx.options.target
        if self.target_url in flow.request.pretty_url:
            request_data = flow.request.text

            for pattern in self.sqli_patterns:
                if re.search(pattern, request_data, re.IGNORECASE):
                    print(f"⚠ Live SQL Injection attempt detected: {flow.request.pretty_url}")
                    print(f"Request Data: {request_data}\n")
                    print("\n Stopping Live Monitoring Due to Detected Attack...\n")
                    sys.exit(0)
            for pattern in self.xss_patterns:
                if re.search(pattern, request_data, re.IGNORECASE):
                    print(f"⚠ Live XSS attempt detected: {flow.request.pretty_url}")
                    print(f"Request Data: {request_data}\n")
                    print("\n Stopping Live Monitoring Due to Detected Attack...\n")
                    sys.exit(0)

            print(f"[MONITORING] Request to {flow.request.pretty_url} is clean.")

# def start():
#     target_url = mitmproxy.ctx.options.target
#     monitor = LiveMonitor(target_url)
#     return monitor.request
addons=[LiveMonitor()]

