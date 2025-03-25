import os
import json
import time
import psutil
import pandas as pd
import subprocess

# Configurations
LOG_PATH = "./appsec-logs/nano_agent.log"  # Adjust if necessary
TARGET = "http://snf-3406.vlab.ac.ke"  # Update with actual target
OUTPUT_CSV = "metrics.csv"
INTERVAL = 60  # Run every 60 seconds

def parse_logs():
    """Parse OpenAppSec logs to count blocked and allowed requests."""
    blocked, allowed = 0, 0
    try:
        with open(LOG_PATH, "r") as log_file:
            for line in log_file:
                try:
                    log_entry = json.loads(line)  # Assuming logs are JSON formatted
                    if "block" in log_entry.get("action", "").lower():
                        blocked += 1
                    else:
                        allowed += 1
                except json.JSONDecodeError:
                    continue  # Skip malformed lines
    except FileNotFoundError:
        print("Log file not found!")

    return {"blocked": blocked, "allowed": allowed}

def run_sqlmap():
    """Simulate an SQL injection attack using SQLMap."""
    cmd = f"sqlmap -u '{TARGET}/login.php' --batch --dbs"
    subprocess.run(cmd, shell=True)

def run_nikto():
    """Run Nikto to scan for vulnerabilities."""
    cmd = f"nikto -h {TARGET}"
    subprocess.run(cmd, shell=True)

def system_metrics():
    """Collect system CPU and memory usage."""
    return {"cpu": psutil.cpu_percent(interval=1), "memory": psutil.virtual_memory().percent}

def save_metrics(data):
    """Save collected metrics to a CSV file."""
    df = pd.DataFrame([data])
    if not os.path.exists(OUTPUT_CSV):
        df.to_csv(OUTPUT_CSV, index=False)
    else:
        df.to_csv(OUTPUT_CSV, mode='a', header=False, index=False)

def main():
    """Automate the attack simulation and metric collection."""
    while True:
        print("Running attack simulations...")
        run_sqlmap()
        run_nikto()

        print("Collecting WAF metrics...")
        waf_metrics = parse_logs()

        print("Collecting system performance metrics...")
        system_usage = system_metrics()

        # Combine data
        metrics = {**waf_metrics, **system_usage, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
        print("Metrics Collected:", metrics)

        print("Saving metrics to CSV...")
        save_metrics(metrics)

        print(f"Sleeping for {INTERVAL} seconds before next iteration...")
        time.sleep(INTERVAL)  # Wait before running again

if __name__ == "__main__":
    main()
