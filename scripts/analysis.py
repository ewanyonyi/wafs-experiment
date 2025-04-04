import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json

# Load the uploaded results
with open("attack_results.json") as f:
    attack_results = json.load(f)

with open("benign_results.json") as f:
    benign_results = json.load(f)

# Function to analyze results per WAF
def analyze_waf_results(attack_data, benign_data):
    waf_stats = {}

    for target in set([r["target"] for r in attack_data]):
        target_attack_results = [r for r in attack_data if r["target"] == target]
        target_benign_results = [r for r in benign_data if r["target"] == target]

        total_attacks = len(target_attack_results)
        total_benign = len(target_benign_results)

        true_positives = sum(
            1 for r in target_attack_results
            # if r["status_code"] in [403, 406, 500] or "blocked" in r["response_snippet"].lower()
            if r["status_code"] in [403, 406, 500]
        )
        false_negatives = total_attacks - true_positives

        false_positives = sum(
            1 for r in target_benign_results
            # if r["status_code"] in [403, 406, 500] or "blocked" in r["response_snippet"].lower()
            if r["status_code"] in [403, 406, 500]
        )
        true_negatives = total_benign - false_positives

        detection_rate = true_positives / total_attacks if total_attacks else 0
        fnr = false_negatives / total_attacks if total_attacks else 0
        fpr = false_positives / total_benign if total_benign else 0
        accuracy = true_negatives / total_benign if total_benign else 0

        waf_stats[target] = {
            "Detection Rate (TPR)": detection_rate,
            "False Negative Rate": fnr,
            "False Positive Rate": fpr,
            "Benign Accuracy": accuracy
        }

    return pd.DataFrame(waf_stats).T.reset_index().rename(columns={"index": "WAF"})

# Analyze results
waf_df = analyze_waf_results(attack_results, benign_results)

# Melt dataframe for seaborn
waf_melted = waf_df.melt(id_vars="WAF", var_name="Metric", value_name="Rate")

# Plot bar chart
plt.figure(figsize=(12, 6))
sns.barplot(data=waf_melted, x="WAF", y="Rate", hue="Metric")
plt.title("WAF Performance Comparison")
plt.ylabel("Rate")
plt.ylim(0, 1)
plt.legend(title="Metric", bbox_to_anchor=(1.05, 1), loc='upper left')
plt.tight_layout()
# plt.show()
plt.tight_layout()
plt.savefig("waf_comparison_chart.png")  # or .pdf, .svg, etc.
print("✅ Chart saved as 'waf_comparison_chart.png'")

