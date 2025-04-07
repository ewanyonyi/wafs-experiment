import json

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# Load the uploaded results
with open("attack_results.json") as f:
    attack_results = json.load(f)

with open("benign_results.json") as f:
    benign_results = json.load(f)

# Function to analyze results per WAF


def analyze_waf_results(attack_data, benign_data):
    waf_stats = {}

    for target in set([r["target"] for r in attack_data]):
        target_attack_results = [
            r for r in attack_data if r["target"] == target]
        target_benign_results = [
            r for r in benign_data if r["target"] == target]

        total_attacks = len(target_attack_results)
        total_benign = len(target_benign_results)

        true_positives = sum(
            1 for r in target_attack_results
            if r["status_code"] in [403, 406, 500]
        )
        false_negatives = total_attacks - true_positives

        false_positives = sum(
            1 for r in target_benign_results
            if r["status_code"] in [403, 406, 500]
        )
        true_negatives = total_benign - false_positives

        avg_attack_response_time = sum(r.get(
            "response_time", 0) for r in target_attack_results) / total_attacks if total_attacks else 0
        avg_benign_response_time = sum(r.get(
            "response_time", 0) for r in target_benign_results) / total_benign if total_benign else 0
        avg_total_response_time = (
            avg_attack_response_time + avg_benign_response_time) / 2

        detection_rate = true_positives / total_attacks if total_attacks else 0
        fnr = false_negatives / total_attacks if total_attacks else 0
        fpr = false_positives / total_benign if total_benign else 0
        accuracy = true_negatives / total_benign if total_benign else 0

        waf_stats[target] = {
            "Detection Rate (TPR)": detection_rate * 100,
            "False Negative Rate": fnr * 100,
            "False Positive Rate": fpr * 100,
            "Benign Accuracy": accuracy * 100,
            "Avg Response Time (ms)": avg_total_response_time * 1000
        }

    return pd.DataFrame(waf_stats).T.reset_index().rename(columns={"index": "WAF"})


# Analyze results
waf_df = analyze_waf_results(attack_results, benign_results)

# Melt dataframe for seaborn
waf_melted = waf_df.melt(id_vars="WAF", var_name="Metric", value_name="Value")

# Split by metric type
performance_metrics = waf_melted[~waf_melted["Metric"].str.contains(
    "Response Time")]
response_time_metrics = waf_melted[waf_melted["Metric"].str.contains(
    "Response Time")]

# Use only as many colors as needed
num_metrics = performance_metrics["Metric"].nunique()
palette = sns.color_palette("Set2", n_colors=num_metrics)

sns.set(style="whitegrid")
sns.set_context("talk")

# --- Detection Performance Chart ---
plt.figure(figsize=(14, 7))
barplot = sns.barplot(
    data=performance_metrics,
    x="WAF",
    y="Value",
    hue="Metric",
    palette=palette
)


for container in barplot.containers:
    barplot.bar_label(container, fmt="%.1f%%",
                      label_type="edge", padding=8, fontsize=10)


plt.title("WAF Detection Performance", fontsize=18)
plt.ylabel("Rate (%)", fontsize=14)
plt.xlabel("WAF", fontsize=14)
plt.xticks(rotation=10)
plt.ylim(0, 100)
plt.legend(title="Metric", bbox_to_anchor=(1.02, 1), loc='upper left')
plt.tight_layout(pad=2.0)
plt.savefig("waf_detection_chart.png")
print("✅ Detection chart saved as 'waf_detection_chart.png'")

# --- Response Time Chart ---
plt.figure(figsize=(10, 6))
barplot2 = sns.barplot(
    data=response_time_metrics,
    x="WAF",
    y="Value",
    hue="WAF",  # fix warning by setting x as hue
    palette="rocket",
    legend=False  # optional: hide legend since x == hue
)

for container in barplot2.containers:
    barplot2.bar_label(container, fmt="%.0f ms",
                       label_type="edge", padding=3, fontsize=10)

plt.title("Average Response Time per WAF", fontsize=18)
plt.ylabel("Time (ms)", fontsize=14)
plt.xlabel("WAF", fontsize=14)
plt.xticks(rotation=10)
plt.tight_layout(pad=2.0)
plt.savefig("waf_response_time_chart.png")
print("✅ Response time chart saved as 'waf_response_time_chart.png'")
