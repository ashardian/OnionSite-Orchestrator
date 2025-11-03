# 🧅 OnionSite Hardening & Monitoring Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Tor](https://img.shields.io/badge/Tor-Integration-purple.svg)
![Security](https://img.shields.io/badge/Status-Hardened-success.svg)

A powerful **automated post-deployment hardening, auditing, and monitoring tool** for `.onion` websites built with the **OnionSite Orchestrator**.  
It ensures your Tor-based infrastructure remains **secure, private, and resilient** through system checks, encryption enforcement, and live service monitoring.

---

## 🚀 Overview

After your `.onion` website is created with the **OnionSite Orchestrator**, this tool performs deep system-level hardening and real-time monitoring of all related services (Tor, Nginx, and system security components).

It automatically:
- Enforces secure configurations.
- Detects misconfigurations.
- Monitors log activity in real time.
- Generates audit reports and encrypted backups.
- Sends optional alerts via email or webhook.

---

## 🧩 Key Features

### 🔐 Security Hardening
- Auto-audit Tor & Nginx configuration files.
- Enforce TLS and safe ciphers for hidden services.
- Secure file permissions and ownership.
- Optionally encrypt and back up hidden service keys.

### 🕵️ Real-Time Monitoring
- Live tracking of Tor, Nginx, and systemd status.
- Alerts for restarts, crashes, or configuration drift.
- Continuous log capture with timestamps.
- Optional webhook or email notifications.

### 🧠 Intelligence & Reporting
- Generates a full JSON or HTML security report.
- Logs every action and event to `/var/log/onionsite-hardener/`.
- Backup and restore support with GPG encryption.

### 🧰 System Integration
- Works seamlessly with OnionSite Orchestrator deployments.
- Uses `ufw`, `journalctl`, `nikto`, and standard Linux utilities.
- Compatible with Debian, Ubuntu, Parrot, and Tails systems.

---

## ⚙️ Installation

Clone the repository and install dependencies:
```bash
git clone https://github.com/YOUR_USERNAME/onionsite-hardener.git
cd onionsite-hardener
sudo chmod +x onionsite_hardening_tool.py
(Dependencies: python3, tor, nginx, ufw, nikto, gpg)

🧭 Usage
1️⃣ Check system status
bash
Copy code
sudo python3 onionsite_hardening_tool.py --check
2️⃣ Apply hardening and secure Tor key
bash
Copy code
sudo python3 onionsite_hardening_tool.py --apply --backup-key --encrypt-key
3️⃣ Generate a detailed report
bash
Copy code
sudo python3 onionsite_hardening_tool.py --report
4️⃣ Start real-time monitoring
bash
Copy code
sudo python3 onionsite_hardening_tool.py --monitor
Logs are stored under:

swift
Copy code
/var/log/onionsite-hardener/hardener.log
/var/log/onionsite-hardener/report.json
🔒 Integration with OnionSite Orchestrator
This tool is the security and reliability layer for your .onion site.
---
```
OnionSite Orchestrator	OnionSite Hardener
Creates Tor hidden service, Nginx, and website	Secures and monitors all services
Handles automatic onion setup	Handles continuous protection
Deploys quickly	Enforces strict, safe configs
Focused on creation	Focused on defense & uptime

Together, they form a complete secure lifecycle for .onion infrastructure — from deployment to protection and long-term stability.

🧾 Example Report Snippet
json
Copy code
{
  "timestamp": "2025-11-03T20:42:11Z",
  "service_status": {
    "tor": "active",
    "nginx": "active"
  },
  "vulnerabilities": [],
  "recommendations": [
    "Enable ufw logging",
    "Ensure HiddenServiceDir permissions are 700"
  ]
}
🧰 Directory Structure
Copy code
onionsite-hardener/
├── onionsite_hardening_tool.py
├── README.md
├── requirements.txt
└── LICENSE
📡 Alerting
You can set up simple webhooks or mail notifications for system anomalies.

Example:

bash
Copy code
sudo python3 onionsite_hardening_tool.py --monitor --alert-webhook "https://yourwebhook.url"
🧩 Future Enhancements
Full HTML dashboard (local web UI)

AI-based log anomaly detection

Integration with SIEM systems (e.g., Wazuh, OpenSearch)

🤝 Contributing
Pull requests and suggestions are welcome.
If you find an issue or want to request a feature, open a GitHub Issue.

🧠 Short Note — How It Helps OnionSite Orchestrator
The OnionSite Orchestrator is your deployment brain — it spins up .onion sites and configures Tor + Nginx.
The OnionSite Hardening & Monitoring Tool is the defense layer — it makes sure everything stays secure, encrypted, and monitored.

Together they create:

A fully automated .onion deployment pipeline.

Continuous integrity checks and hardened configurations.

A self-healing, auditable, and stealth-ready onion infrastructure.

💬 Author
Ashar Dian
🕸️ Onion Security Automation Developer
