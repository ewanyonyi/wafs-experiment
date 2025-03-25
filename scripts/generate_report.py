import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import Image

# Load the collected metrics
df = pd.read_csv("metrics.csv")

# Convert timestamp to datetime format
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Set seaborn theme
sns.set_theme(style="darkgrid")

# 📌 Generate and save Blocked vs Allowed graph
plt.figure(figsize=(10, 5))
sns.lineplot(x=df["timestamp"], y=df["blocked"], label="Blocked Requests", marker="o", color="red")
sns.lineplot(x=df["timestamp"], y=df["allowed"], label="Allowed Requests", marker="s", color="green")
plt.title("Blocked vs Allowed Requests Over Time")
plt.xlabel("Timestamp")
plt.ylabel("Number of Requests")
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("blocked_vs_allowed.png")
plt.close()

# 📌 Generate and save CPU & Memory usage graph
plt.figure(figsize=(10, 5))
sns.lineplot(x=df["timestamp"], y=df["cpu"], label="CPU Usage (%)", marker="o", color="blue")
sns.lineplot(x=df["timestamp"], y=df["memory"], label="Memory Usage (%)", marker="s", color="purple")
plt.title("CPU & Memory Usage Over Time")
plt.xlabel("Timestamp")
plt.ylabel("Usage (%)")
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("cpu_memory_usage.png")
plt.close()

# 📌 Generate PDF Report
pdf_filename = "waf_analysis_report.pdf"
c = canvas.Canvas(pdf_filename, pagesize=letter)

# 📌 Title
c.setFont("Helvetica-Bold", 16)
c.drawString(200, 750, "WAF Performance Analysis Report")

# 📌 Summary Statistics
c.setFont("Helvetica", 12)
c.drawString(50, 720, f"Total Requests: {df['allowed'].sum() + df['blocked'].sum()}")
c.drawString(50, 700, f"Total Blocked: {df['blocked'].sum()} ({(df['blocked'].sum() / df['allowed'].sum() + df['blocked'].sum())*100:.2f}%)")
c.drawString(50, 680, f"False Positives: TBD")  # You can automate this if needed
c.drawString(50, 660, f"Avg CPU Usage: {df['cpu'].mean():.2f}%")
c.drawString(50, 640, f"Avg Memory Usage: {df['memory'].mean():.2f}%")

# 📌 Attach Images
c.drawImage("blocked_vs_allowed.png", 50, 400, width=500, height=200)
c.drawImage("cpu_memory_usage.png", 50, 150, width=500, height=200)

# 📌 Observations Section
c.showPage()
c.setFont("Helvetica-Bold", 14)
c.drawString(50, 750, "Observations & Analysis")

c.setFont("Helvetica", 12)
observations = [
    "1. The WAF blocked X% of attacks successfully.",
    "2. False positives need further investigation.",
    "3. CPU usage spiked during high-traffic attack simulations.",
    "4. Memory consumption remained stable, indicating efficient handling.",
    "5. Further tests should be done with different attack types."
]

y_position = 700
for obs in observations:
    c.drawString(50, y_position, obs)
    y_position -= 20

c.save()
print(f"Report saved as {pdf_filename}")
