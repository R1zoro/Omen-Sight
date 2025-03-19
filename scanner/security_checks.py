import requests

def check_security_headers(target_url):
    """Check for missing HTTP security headers."""
    print(f"\n[+] Checking security headers for {target_url}...")

    try:
        response = requests.get(target_url, timeout=5)
        headers = response.headers

        missing_headers = []
        required_headers = {
            "Content-Security-Policy": "Helps prevent XSS attacks.",
            "X-Frame-Options": "Prevents Clickjacking attacks.",
            "X-Content-Type-Options": "Prevents MIME-type sniffing.",
            "Strict-Transport-Security": "Forces HTTPS connections.",
            "Referrer-Policy": "Controls how referrer information is sent.",
        }

        for header, description in required_headers.items():
            if header not in headers:
                missing_headers.append(f"[-] {header} missing ({description})")

        return missing_headers if missing_headers else "[+] All important security headers are present."
    except requests.exceptions.RequestException as e:
        return f"Error retrieving headers: {e}"