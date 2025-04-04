import json
import time
import requests

# Target instances (same as attack script)
TARGETS = {
    "No_WAF": "http://snf-6360.vlab.ac.ke",
    "CrowdSec": "http://snf-3406.vlab.ac.ke",
    "ModSecurity": "http://snf-3351.vlab.ac.ke"
}

# Benign test cases (use same endpoints but with safe data)
BENIGN_REQUESTS = [
    {
        "type": "Search (Safe)",
        "endpoint": "/test.php",
        "method": "GET",
        "params": {"q": "hello"}
    },
    {
        "type": "File View (Safe)",
        "endpoint": "/test.php",
        "method": "GET",
        "params": {"file": "info.txt"}
    },
    {
        "type": "Ping (Safe)",
        "endpoint": "/ping.php",
        "method": "POST",
        "data": {"ip": "127.0.0.1"}
    },
    {
        "type": "HTML Form (Safe)",
        "endpoint": "/htmli_get.php",
        "method": "GET",
        "params": {"firstname": "John", "lastname": "Doe", "form": "submit"}
    },
    {
        "type": "Language Select (Safe)",
        "endpoint": "/rlfi.php",
        "method": "GET",
        "params": {"language": "english"}
    },
    {
        "type": "Book Search (Safe)",
        "endpoint": "/sqli_1.php",
        "method": "GET",
        "params": {"title": "harry potter", "action": "search"}
    },
    {
        "type": "Homepage Visit",
        "endpoint": "/",
        "method": "GET"
    }
]

def test_benign_requests(target_name, base_url):
    results = []

    for req in BENIGN_REQUESTS:
        url = base_url + req["endpoint"]
        method = req["method"]

        print(f"\n📗 Sending benign request [{req['type']}] to {target_name} ({url})...")

        try:
            start_time = time.perf_counter()

            if method == "GET":
                response = requests.get(url, params=req.get("params"), timeout=5)
            elif method == "POST":
                response = requests.post(url, data=req.get("data"), timeout=5)
            else:
                continue

            end_time = time.perf_counter()
            elapsed = end_time - start_time

            result = {
                "target": target_name,
                "request_type": req["type"],
                "endpoint": req["endpoint"],
                "method": method,
                "request": req.get("params") if method == "GET" else req.get("data"),
                "status_code": response.status_code,
                # "response_snippet": response.text[:200],
                "response_time_seconds": round(elapsed, 4)
            }

            results.append(result)

            if response.status_code in [403, 406, 500] or "blocked" in response.text.lower():
                print(f"🚨 FALSE POSITIVE? Benign request BLOCKED by {target_name} (Status: {response.status_code})")
            else:
                print(f"✅ Benign request SUCCESSFUL on {target_name} (Status: {response.status_code})")

            time.sleep(1)

        except requests.exceptions.RequestException as e:
            print(f"❌ Error with benign request on {target_name}: {e}")

    return results

# Run genuine requests on all targets
all_benign_results = []

for name, url in TARGETS.items():
    results = test_benign_requests(name, url)
    all_benign_results.extend(results)

# Save to file
with open("benign_results.json", "w") as f:
    json.dump(all_benign_results, f, indent=4)

print("\n✅ Benign traffic simulation completed. Results saved to benign_results.json.")
