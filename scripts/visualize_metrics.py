import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load data
df = pd.read_csv("metrics.csv")

# Convert timestamp to datetime format
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Set seaborn style
sns.set_theme(style="darkgrid")

# Create a figure with two subplots
fig, axes = plt.subplots(2, 1, figsize=(12, 10))

# 📌 Plot 1: Blocked vs Allowed Requests Over Time
sns.lineplot(x=df["timestamp"], y=df["blocked"], label="Blocked Requests", ax=axes[0], marker="o", color="red")
sns.lineplot(x=df["timestamp"], y=df["allowed"], label="Allowed Requests", ax=axes[0], marker="s", color="green")
axes[0].set_title("Blocked vs Allowed Requests Over Time")
axes[0].set_xlabel("Timestamp")
axes[0].set_ylabel("Number of Requests")
axes[0].legend()
axes[0].tick_params(axis="x", rotation=45)

# 📌 Plot 2: CPU & Memory Usage Over Time
sns.lineplot(x=df["timestamp"], y=df["cpu"], label="CPU Usage (%)", ax=axes[1], marker="o", color="blue")
sns.lineplot(x=df["timestamp"], y=df["memory"], label="Memory Usage (%)", ax=axes[1], marker="s", color="purple")
axes[1].set_title("System Performance Over Time")
axes[1].set_xlabel("Timestamp")
axes[1].set_ylabel("Usage (%)")
axes[1].legend()
axes[1].tick_params(axis="x", rotation=45)

# Adjust layout and show the plots
plt.tight_layout()
plt.show()
