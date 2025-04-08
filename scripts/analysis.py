"""
WAF Analysis Script

Analyzes WAF performance using attack and benign traffic JSON results.

Outputs:
- waf_detection_chart.png
- waf_response_time_chart.png
"""

import argparse
import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# --- Config ---
DETECTION_CODES = {403, 406, 500}
sns.set_theme(style="whitegrid", context="notebook")


def load_data(file_path):
    with open(file_path) as f:
        return json.load(f)


def analyze_waf_results(attack_data, benign_data):
    waf_stats = {}

    for target in set(r["target"] for r in attack_data):
        target_attack_results = [
            r for r in attack_data if r["target"] == target]
        target_benign_results = [
            r for r in benign_data if r["target"] == target]

        total_attacks = len(target_attack_results)
        total_benign = len(target_benign_results)

        true_positives = sum(
            1 for r in target_attack_results if r["status_code"] in DETECTION_CODES)
        false_negatives = total_attacks - true_positives

        false_positives = sum(
            1 for r in target_benign_results if r["status_code"] in DETECTION_CODES)
        true_negatives = total_benign - false_positives

        # Convert to ms
        avg_attack_rt = (sum(r.get("response_time_seconds", 0)
                         for r in target_attack_results) / total_attacks) * 1000 if total_attacks else 0
        avg_benign_rt = (sum(r.get("response_time_seconds", 0)
                         for r in target_benign_results) / total_benign) * 1000 if total_benign else 0
        avg_total_rt = (avg_attack_rt + avg_benign_rt) / 2

        detection_rate = true_positives / total_attacks if total_attacks else 0
        fnr = false_negatives / total_attacks if total_attacks else 0
        fpr = false_positives / total_benign if total_benign else 0
        accuracy = true_negatives / total_benign if total_benign else 0

        waf_stats[target] = {
            "Detection Rate (TPR)": detection_rate * 100,
            "False Negative Rate": fnr * 100,
            "False Positive Rate": fpr * 100,
            "Benign Accuracy": accuracy * 100,
            "Avg Response Time (ms)": avg_total_rt,
            "Total Attacks": total_attacks,
            "Total Benign": total_benign,
        }

    return pd.DataFrame(waf_stats).T.reset_index().rename(columns={"index": "WAF"})


def plot_detection_chart(df):
    melted = df.melt(id_vars="WAF", value_vars=[
        "Detection Rate (TPR)", "False Negative Rate", "False Positive Rate", "Benign Accuracy"
    ], var_name="Metric", value_name="Value")

    plt.figure(figsize=(14, 7))
    barplot = sns.barplot(
        data=melted, x="WAF", y="Value", hue="Metric", palette="Set2"
    )

    for container in barplot.containers:
        labels = [f"{bar.get_height():.1f}%" if bar.get_height() >
                  1 else "" for bar in container]
        barplot.bar_label(container, labels=labels,
                          label_type='edge', padding=6, fontsize=9)

    plt.title("WAF Detection Performance", fontsize=18,
              pad=20)  # 👈 Added padding here
    plt.ylabel("Rate (%)", fontsize=14)
    plt.xlabel("WAF", fontsize=14)
    plt.xticks(rotation=10)
    plt.ylim(0, 100)
    plt.legend(title="Metric", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout(pad=2)  # 👈 More room for title/legend
    plt.savefig("waf_detection_chart.png")
    print("✅ Detection chart saved as 'waf_detection_chart.png'")



def plot_response_time_chart(df):
    melted = df[["WAF", "Avg Response Time (ms)"]]

    plt.figure(figsize=(10, 6))
    barplot = sns.barplot(data=melted, x="WAF", y="Avg Response Time (ms)", palette="rocket")

    for container in barplot.containers:
        barplot.bar_label(container, fmt="%.0f ms",
                          label_type="edge", padding=3, fontsize=10)

    plt.title("Average Response Time per WAF", fontsize=18, pad=20)
    plt.ylabel("Time (ms)", fontsize=14)
    plt.xlabel("WAF", fontsize=14)
    plt.xticks(rotation=10)
    plt.tight_layout(pad=2)
    plt.legend(title="WAF", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.savefig("waf_response_time_chart.png")
    print("✅ Response time chart saved as 'waf_response_time_chart.png'")


def main(attack_file, benign_file):
    attack_data = load_data(attack_file)
    benign_data = load_data(benign_file)

    stats_df = analyze_waf_results(attack_data, benign_data)
    plot_detection_chart(stats_df)
    plot_response_time_chart(stats_df)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze WAF results from JSON files.")
    parser.add_argument("--attack", default="attack_results.json", help="Path to attack results JSON file.")
    parser.add_argument("--benign", default="benign_results.json", help="Path to benign results JSON file.")
    args = parser.parse_args()

    main(args.attack, args.benign)
