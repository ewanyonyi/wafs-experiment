# Description: Simulate attacks on different targets to test WAF effectiveness
import json
import time

import requests

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
        "endpoint": "/htmli_get.php",
        "method": "GET",
        "params": {"firstname": "hello", "lastname": "<b>world<%2Fb>", "form": "submit"}
    },
    {
        "type": "Remote & Local File Inclusion (RFI/LFI)",
        "endpoint": "/rlfi.php",
        "method": "GET",
        "params": {"language": "/etc/passwd"}
    },
    {
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php?",
        "method": "GET",
        "params": {"title": "blah%27+or+1=1--%20", "action": "search"}
    }
    
    #     {"type": "Sensitive File Access", "endpoint": "/phpinfo.php", "method": "GET", "check_status": 200},
    #     {"type": "Sensitive File Access", "endpoint": "/config.inc", "method": "GET", "check_status": 200},
    #     {"type": "Sensitive Directory Listing", "endpoint": "/passwords/", "method": "GET", "check_status": 200},
    #     {"type": "Sensitive Directory Listing", "endpoint": "/db/", "method": "GET", "check_status": 200},
    #     {"type": "Sensitive Directory Listing", "endpoint": "/documents/", "method": "GET", "check_status": 200},
    #     # Cookie Security Check
    #     {"type": "Cookie Security Check", "endpoint": "/", "method": "GET", "check_headers": ["Set-Cookie"]}
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
                "params": attack["params"],
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

