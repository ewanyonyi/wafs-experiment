import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict

# Load your attack results file
with open("attack_results.json") as f:
    attack_data = json.load(f)

BLOCK_CODES = {403, 406, 500}

# Summary per WAF
summary = defaultdict(lambda: {
    "Total": 0, "Blocked": 0, "Missed": 0, 
    "Total Response Time": 0.0
})

for entry in attack_data:
    target = entry["target"]
    status = entry["status_code"]
    rt = entry.get("response_time_seconds", 0)

    summary[target]["Total"] += 1
    summary[target]["Total Response Time"] += rt

    if status in BLOCK_CODES:
        summary[target]["Blocked"] += 1
    else:
        summary[target]["Missed"] += 1

# Convert to DataFrame
df_summary = pd.DataFrame([
    {
        "WAF": target,
        "Total Attacks": data["Total"],
        "Blocked": data["Blocked"],
        "Missed": data["Missed"],
        "Detection Rate (TPR) %": round((data["Blocked"] / data["Total"]) * 100, 2),
        "False Negative Rate (FNR) %": round((data["Missed"] / data["Total"]) * 100, 2),
        "Avg Response Time (ms)": round((data["Total Response Time"] / data["Total"]) * 1000, 2)
    }
    for target, data in summary.items()
])

df_summary.sort_values(by="Detection Rate (TPR) %", ascending=False, inplace=True)
df_summary.reset_index(drop=True, inplace=True)

# Save summary CSV
df_summary.to_csv("waf_detection_summary.csv", index=False)
print("✅ CSV saved as waf_detection_summary.csv")

# Bar chart: Detection vs FNR
sns.set_theme(style="whitegrid")
plt.figure(figsize=(10, 6))

melted = df_summary.melt(id_vars="WAF", 
                         value_vars=["Detection Rate (TPR) %", "False Negative Rate (FNR) %"],
                         var_name="Metric", value_name="Value")

sns.barplot(data=melted, x="WAF", y="Value", hue="Metric", palette="Set2")
plt.title("WAF Detection vs False Negative Rate")
plt.ylabel("Percentage (%)")
plt.ylim(0, 100)
plt.tight_layout()
plt.savefig("waf_detection_vs_fnr_chart.png")
print("📊 Detection chart saved as waf_detection_vs_fnr_chart.png")

# Response time chart
plt.figure(figsize=(8, 6))
sns.barplot(data=df_summary, x="WAF", y="Avg Response Time (ms)", palette="rocket")
plt.title("Average Response Time by WAF")
plt.ylabel("Time (ms)")
plt.tight_layout()
plt.savefig("waf_response_time_chart.png")
print("⏱️ Response time chart saved as waf_response_time_chart.png")

# Breakdown by attack type
attack_type_stats = defaultdict(lambda: defaultdict(lambda: {"Blocked": 0, "Total": 0}))

for entry in attack_data:
    target = entry["target"]
    attack_type = entry["attack_type"]
    status = entry["status_code"]

    attack_type_stats[attack_type][target]["Total"] += 1
    if status in BLOCK_CODES:
        attack_type_stats[attack_type][target]["Blocked"] += 1

# Flatten per-attack-type stats
attack_type_rows = []
for attack_type, wafs in attack_type_stats.items():
    row = {"Attack Type": attack_type}
    for waf, stats in wafs.items():
        tpr = (stats["Blocked"] / stats["Total"]) * 100 if stats["Total"] else 0
        row[f"{waf} Detection %"] = round(tpr, 2)
    attack_type_rows.append(row)

df_attacks = pd.DataFrame(attack_type_rows)
df_attacks.to_csv("waf_attack_type_breakdown.csv", index=False)
print("📄 Attack-type breakdown saved as waf_attack_type_breakdown.csv")
