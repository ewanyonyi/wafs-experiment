import json

# Load both attack and benign results
with open("attack_results.json") as f:
    attack_data = json.load(f)

with open("benign_results.json") as f:
    benign_data = json.load(f)

# Define what status codes or response text suggest a block
def is_blocked(response):
    if response["status_code"] in [403, 406, 500]:
        return True
    elif "blocked" in response.get("response_snippet", "").lower():
        return True
    return False

# Structure: {target: {TP, FN, FP, TN}}
results = {}

# Process attacks (True Positives and False Negatives)
for entry in attack_data:
    target = entry["target"]
    blocked = is_blocked(entry)

    if target not in results:
        results[target] = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}

    if blocked:
        results[target]["TP"] += 1
    else:
        results[target]["FN"] += 1

# Process benign (False Positives and True Negatives)
for entry in benign_data:
    target = entry["target"]
    blocked = is_blocked(entry)

    if target not in results:
        results[target] = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}

    if blocked:
        results[target]["FP"] += 1
    else:
        results[target]["TN"] += 1

# Output results
print("\n📊 WAF Evaluation Metrics:\n")

for target, scores in results.items():
    TP = scores["TP"]
    FN = scores["FN"]
    FP = scores["FP"]
    TN = scores["TN"]

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) else 0

    print(f"🔹 Target: {target}")
    print(f"   ✅ True Positives:   {TP}")
    print(f"   ❌ False Negatives:  {FN}")
    print(f"   🚨 False Positives:  {FP}")
    print(f"   👍 True Negatives:   {TN}")
    print(f"   📈 Precision:        {precision:.2f}")
    print(f"   📈 Recall:           {recall:.2f}")
    print(f"   📈 F1 Score:         {f1_score:.2f}")
    print("")

