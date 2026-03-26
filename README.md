🚀 Gmail Security Monitoring with Wazuh (Custom Integration)
<p align="center"> <b>🔥 What if your inbox is under attack… and your SIEM doesn’t even know?</b> </p>
🎯 The Idea

Traditional SIEMs monitor infrastructure…
But your email inbox? Completely invisible.

This project changes that.

I built a Gmail → Wazuh integration from scratch
— no plugins, no marketplace, no native support.

✅ Features
✔ Real-time email monitoring
✔ Phishing detection
✔ Suspicious domain alerts
✔ Burst activity detection
🧠 Problem Statement

Modern attacks don’t break in — they log in.

📩 Phishing emails bypass filters
🔑 Credential harvesting emails go unnoticed
💰 Fake invoices trick users
🌐 Suspicious domains slip through

❌ And your SIEM sees nothing

💡 Solution

We turn Gmail into a log source for Wazuh

Gmail API → Python Collector → Log File → Wazuh → Alerts 🚨
🏗️ Architecture
Gmail Account
      │
      ▼
Gmail API (OAuth2)
      │
      ▼
gmail_collector.py
      │
      ▼
/var/ossec/logs/gmail.log
      │
      ▼
Wazuh Logcollector
      │
      ▼
Decoders → Rules → Alerts

📌 Tip: Add a diagram image here for better visualization

🧾 Log Format (Critical Design)
integration=gmail from="user@example.com" subject="Urgent Invoice" timestamp="2026-03-18T12:00:00Z"

✔ Simple
✔ Predictable
✔ Decoder-friendly

🐍 Python Collector (Core Engine)
line = f'integration=gmail from="{sender}" subject="{subject}" timestamp="{timestamp}"'
🔐 Sanitization (VERY IMPORTANT)
def sanitise_field(value):
    value = value.replace('"', "'")
    value = re.sub(r"[\x00-\x1f]", " ", value)
    return value.strip()

✔ Prevents decoder break
✔ Prevents Wazuh parsing errors

🧩 Wazuh Decoders
<decoder name="gmail_parent">
  <prematch>^integration=gmail </prematch>
</decoder>

<decoder name="gmail_fields">
  <parent>gmail_parent</parent>
  <regex>^integration=gmail\s+from="([^"]+)"\s+subject="([^"]+)"\s+timestamp="([^"]+)"</regex>
  <order>srcuser, extra_data, id</order>
</decoder>
🚨 Detection Rules
🔥 Phishing Keywords
<match type="pcre2">(?i)subject="[^"]*password[^"]*"</match>
🌐 Suspicious Domains
<match type="pcre2">from="[^"]+@(?!(gmail|yahoo|outlook)\.)</match>
⚡ Burst Detection
frequency="10" timeframe="60"
📊 What You Detect
Threat Type	Detection
Phishing Emails	✅
Fake Invoices	✅
Password Attacks	✅
Suspicious Domains	✅
Email Flooding	✅
🧪 Testing
python3 gmail_collector.py --test-line
tail -f /var/ossec/logs/alerts.log
⚙️ Setup Overview
1️⃣ Google Cloud
Create project
Enable Gmail API
Create OAuth credentials
Download credentials.json
2️⃣ Python Setup
pip install google-auth google-auth-oauthlib google-api-python-client
3️⃣ Run Collector
python3 gmail_collector.py
4️⃣ Wazuh Config
<localfile>
  <log_format>syslog</log_format>
  <location>/var/ossec/logs/gmail.log</location>
</localfile>
5️⃣ Restart Wazuh
sudo systemctl restart wazuh-manager
⏱️ Automation (Cron Job)
*/5 * * * * python3 /opt/wazuh-gmail/gmail_collector.py
🧠 Lessons Learned
⚠️ JSON logs can break Wazuh (Too many fields error)
⚠️ Wazuh XML is strict (no headers allowed)
⚠️ Sanitization is EVERYTHING
⚠️ Debugging SIEM ≠ debugging code
🔥 Why This Matters

This proves:

👉 Wazuh is not limited to built-in integrations
👉 You can monitor ANY data source
👉 Even your personal Gmail security
🚀 Future Improvements
📎 Attachment scanning
🤖 SOAR automation
📧 Auto-label phishing emails
📊 Dashboard visualizations
🤝 Contribute / Connect

If you build something like this — I’d love to see it.

Let’s push open-source security further 🚀

⭐ Support

If this helped you:

⭐ Star the repo
🔁 Share with others
💬 Reach out for collaboration
<p align="center"> <b>Security is not about tools — it's about visibility.</b> </p>
