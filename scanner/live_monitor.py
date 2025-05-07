# --- scanner/live_monitor.py ---

from mitmproxy import http
from mitmproxy import ctx
import re

class LiveMonitor:
    def __init__(self):
        # ... (sqli_patterns, xss_patterns remain the same) ...
        self.sqli_patterns = [
            r"union\s+select", r"or\s+1=1", r"'\s*--", r'"\s*--',
            r"sleep\s*\(", r"benchmark\s*\(", r"select\s+.*\s+from",
            r"insert\s+into", r"delete\s+from", r"update\s+.*\s+set",
        ]
        self.xss_patterns = [
            r"<script.*?>", r"javascript\s*:", r"onerror\s*=",
            r"onload\s*=", r"onmouseover\s*=", r"<iframe.*?>",
            r"<svg.*?>", r"<\w+\s+on\w+\s*=",
        ]

    def load(self, loader):
        ctx.log.info("[OmenSight LiveMonitor] Addon loaded and active.")

    def request(self, flow: http.HTTPFlow) -> None:
        # ... (request analysis logic remains the same) ...
        detected_issue_type = None
        matched_pattern = None

        # Analyze Query Parameters
        for name, value in flow.request.query.fields:
            for pattern in self.sqli_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    detected_issue_type = "SQLi (Query)"
                    matched_pattern = pattern
                    break
            if detected_issue_type: break
            if not detected_issue_type:
                for pattern in self.xss_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        detected_issue_type = "XSS (Query)"
                        matched_pattern = pattern
                        break
            if detected_issue_type: break

        if not detected_issue_type and flow.request.content:
            content_type = flow.request.headers.get("content-type", "").lower()
            if "application/x-www-form-urlencoded" in content_type or \
               "application/json" in content_type or \
               "multipart/form-data" in content_type or \
               "text/" in content_type:
                request_body_text = flow.request.get_text(strict=False)
                if request_body_text:
                    for pattern in self.sqli_patterns:
                        if re.search(pattern, request_body_text, re.IGNORECASE):
                            detected_issue_type = "SQLi (Body)"
                            matched_pattern = pattern
                            break
                    if not detected_issue_type:
                        for pattern in self.xss_patterns:
                            if re.search(pattern, request_body_text, re.IGNORECASE):
                                detected_issue_type = "XSS (Body)"
                                matched_pattern = pattern
                                break
        if detected_issue_type:
            log_message = (
                f"[OmenSight] Potential {detected_issue_type} detected in request to: {flow.request.pretty_url} "
                f"(Pattern: {matched_pattern})"
            )
            ctx.log.warn(log_message)
            if "SQLi" in detected_issue_type:
                flow.marked = ":syringe:"
                flow.metadata["omensight_finding"] = f"Potential {detected_issue_type}"
            elif "XSS" in detected_issue_type:
                flow.marked = ":warning:"
                flow.metadata["omensight_finding"] = f"Potential {detected_issue_type}"

    def done(self): # Addon lifecycle event
        """Called when the addon is shutting down."""
        ctx.log.info("[OmenSight LiveMonitor] Addon shutting down.")

addons = [
    LiveMonitor()
]