The Onionsite Hardening & Monitor Tool is an automated security enhancer and real-time monitoring companion for your .onion website infrastructure.
It works seamlessly alongside the Onionsite Orchestrator, providing system hardening, security auditing, backup automation, WAF setup, and live log monitoring for services like Tor and Nginx.

This tool ensures that your .onion deployment remains secure, compliant, and resilient against common attack vectors.

🛡️ Features
Category	Description
🔍 Security Audit	Automatically checks Tor configuration, Nginx status, firewall setup, Fail2Ban, and system protections.
🧩 Automatic Hardening	Applies secure configurations to Tor and Nginx, adds restrictive systemd sandboxing, and configures Unattended Upgrades.
🔐 Key Protection	Backs up and optionally encrypts your Hidden Service private key using GPG.
🌐 Firewall Setup	Automatically configures UFW to block all inbound except localhost.
🧱 WAF Integration	Installs and enables ModSecurity2 (Web Application Firewall) for Nginx or Apache.
📊 Real-Time Monitoring	Tails systemd logs and Nginx access/error logs in real-time, detecting anomalies and failed requests.
📦 Reporting	Generates detailed JSON security reports containing audit results, actions taken, and vulnerability scans.
⚙️ Systemd Integration	Installs a persistent monitor service that runs automatically at boot.
📢 Alerting System	Supports Slack/webhook alerts and email notifications for anomalies or service failures.
⚡ Quick Start
1️⃣ Installation
sudo apt update
sudo apt install python3 git -y
git clone https://github.com/<yourusername>/onionsite-hardener.git
cd onionsite-hardener

2️⃣ Run Audit Check
sudo python3 onionsite_hardening_tool.py --check


This performs a deep security audit of:

Tor configuration (/etc/tor/torrc)

Hidden Service permissions

Nginx listener and security headers

System hardening tools (Fail2Ban, nftables, UFW)

3️⃣ Apply Full Hardening
sudo python3 onionsite_hardening_tool.py --apply --enable-waf --setup-firewall --backup-key --encrypt-key


This:

Backs up all critical configs and keys

Applies Nginx/Tor sandboxing

Enforces secure permissions

Installs ModSecurity WAF

Configures firewall and auto-updates

4️⃣ Generate a Security Report
sudo python3 onionsite_hardening_tool.py --report


Find the report in:

/var/log/onionsite-hardener/report.json

5️⃣ Enable Background Monitoring Service
sudo python3 onionsite_hardening_tool.py --install-service --webhook https://hooks.slack.com/services/... --admin-email you@example.com


This installs a systemd service:

/etc/systemd/system/onionsite-hardener-monitor.service


and starts continuous log monitoring for Tor and Nginx.

6️⃣ Run Live Monitor Manually
sudo python3 onionsite_hardening_tool.py --monitor


You’ll see live logs with automatic detection of 4xx/5xx HTTP errors and Tor service issues.

🧩 Integration with Onionsite Orchestrator
Aspect	Onionsite Orchestrator	Hardening Tool
Purpose	Deploys and configures .onion websites automatically.	Hardens, secures, and monitors those deployed sites.
Focus	Automation & setup	Security, resilience, compliance
Outcome	Running .onion website	Hardened, monitored, and self-healing .onion website
Security	Basic Tor and Nginx setup	Advanced Nginx/Tor hardening, firewall, WAF, key backup
Logs & Alerts	Deployment logs	Real-time monitoring, Slack/email alerts

Together, they create a full-stack .onion site management suite:

The Orchestrator builds and configures the site.

The Hardener Tool locks it down, audits, and monitors continuously.

📁 File Structure
onionsite-hardener/
├── onionsite_hardening_tool.py       # Main Python executable
├── README.md                         # Documentation
├── /var/backups/onionsite-hardener/  # Auto-created backups
├── /var/log/onionsite-hardener/      # Security reports & logs
└── /etc/systemd/system/onionsite-hardener-monitor.service

📋 Example Use Cases

🧱 Hardening an .onion site right after deployment by the Orchestrator

🔎 Generating compliance/security audit reports for internal review

📡 Setting up continuous service monitoring with Slack/webhook alerts

🔐 Securing Hidden Service keys with encryption and backup

⚠️ Requirements

Python 3.6+

Root privileges (for system modifications)

Linux environment (tested on Debian, Ubuntu, Parrot, Mint)

Optional: nikto, gpg, curl, ufw, fail2ban

🧩 Recommended Usage Workflow
# 1. Deploy .onion website
sudo onionsite-orchestrator --install

# 2. Immediately harden and secure
sudo python3 onionsite_hardening_tool.py --apply --enable-waf --setup-firewall

# 3. Verify system integrity
sudo python3 onionsite_hardening_tool.py --check --report

# 4. Enable continuous monitoring
sudo python3 onionsite_hardening_tool.py --install-service
