import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import Image

# Load collected metrics
df = pd.read_csv("metrics.csv")

# Convert timestamp to datetime format
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Set seaborn theme
sns.set_theme(style="darkgrid")

# 📌 Plot Blocked Requests Comparison
plt.figure(figsize=(10, 5))
sns.lineplot(x=df["timestamp"], y=df[df["waf_type"] == "openappsec"]["blocked"], label="OpenAppSec Blocked", marker="o", color="red")
sns.lineplot(x=df["timestamp"], y=df[df["waf_type"] == "modsecurity"]["blocked"], label="ModSecurity Blocked", marker="s", color="blue")
plt.title("Blocked Requests: OpenAppSec vs ModSecurity")
plt.xlabel("Timestamp")
plt.ylabel("Blocked Requests")
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("comparison_blocked.png")
plt.close()

# 📌 Plot CPU Usage Comparison
plt.figure(figsize=(10, 5))
sns.lineplot(x=df["timestamp"], y=df[df["waf_type"] == "openappsec"]["cpu"], label="OpenAppSec CPU", marker="o", color="purple")
sns.lineplot(x=df["timestamp"], y=df[df["waf_type"] == "modsecurity"]["cpu"], label="ModSecurity CPU", marker="s", color="orange")
plt.title("CPU Usage: OpenAppSec vs ModSecurity")
plt.xlabel("Timestamp")
plt.ylabel("CPU Usage (%)")
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("comparison_cpu.png")
plt.close()

# 📌 Generate PDF Report
pdf_filename = "waf_comparison_report.pdf"
c = canvas.Canvas(pdf_filename, pagesize=letter)

# 📌 Title
c.setFont("Helvetica-Bold", 16)
c.drawString(200, 750, "WAF Performance Comparison Report")

# 📌 Summary Statistics
c.setFont("Helvetica", 12)
c.drawString(50, 720, "🔹 OpenAppSec: Total Blocked: {}, Avg CPU: {:.2f}%".format(
    df[df["waf_type"] == "openappsec"]["blocked"].sum(), 
    df[df["waf_type"] == "openappsec"]["cpu"].mean()
))
c.drawString(50, 700, "🔹 ModSecurity: Total Blocked: {}, Avg CPU: {:.2f}%".format(
    df[df["waf_type"] == "modsecurity"]["blocked"].sum(), 
    df[df["waf_type"] == "modsecurity"]["cpu"].mean()
))

# 📌 Attach Images
c.drawImage("comparison_blocked.png", 50, 400, width=500, height=200)
c.drawImage("comparison_cpu.png", 50, 150, width=500, height=200)

# 📌 Observations
c.showPage()
c.setFont("Helvetica-Bold", 14)
c.drawString(50, 750, "Observations & Analysis")

c.setFont("Helvetica", 12)
observations = [
    "1. OpenAppSec blocked X% more requests than ModSecurity.",
    "2. False positive rates need to be analyzed.",
    "3. OpenAppSec had Y% lower CPU usage on average.",
    "4. Performance impact on server response time should be checked.",
    "5. Additional tests required for zero-day threats."
]

y_position = 700
for obs in observations:
    c.drawString(50, y_position, obs)
    y_position -= 20

c.save()
print(f"Report saved as {pdf_filename}")
