# 🧅 OnionSite Hardening & Monitoring Tool

A comprehensive Python-based hardening and monitoring toolkit for securing and maintaining Tor (.onion) websites.  
This tool strengthens Nginx, Tor services, and firewall configurations while providing continuous monitoring, vulnerability scanning, and secure key management.

---

## ⚙️ Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/YOUR_USERNAME/onionsite-hardener.git
cd onionsite-hardener
sudo chmod +x onionsite_hardening_tool.py
# Dependencies: python3, tor, nginx, ufw, nikto, gpg
```

---

## 🧭 Usage

### 1️⃣ Check system status
```bash
sudo python3 onionsite_hardening_tool.py --check
```

### 2️⃣ Apply hardening and secure Tor key
```bash
sudo python3 onionsite_hardening_tool.py --apply --backup-key --encrypt-key
```

### 3️⃣ Generate a detailed report
```bash
sudo python3 onionsite_hardening_tool.py --report
```

### 4️⃣ Start real-time monitoring
```bash
sudo python3 onionsite_hardening_tool.py --monitor
```

Logs are stored under:
```
/var/log/onionsite-hardener/hardener.log
/var/log/onionsite-hardener/report.json
```

---

## 🔒 Integration with OnionSite Orchestrator

This tool is the **security and reliability layer** for your .onion site.

| OnionSite Orchestrator | OnionSite Hardener |
|--------------------------|--------------------|
| Creates Tor hidden service, Nginx, and website | Secures and monitors all services |
| Handles automatic onion setup | Handles continuous protection |
| Deploys quickly | Enforces strict, safe configs |
| Focused on creation | Focused on defense & uptime |

**Together, they form a complete secure lifecycle for .onion infrastructure — from deployment to protection and long-term stability.**

---

## 🧾 Example Report Snippet

```json
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
```

---

## 🧰 Directory Structure

```
onionsite-hardener/
├── onionsite_hardening_tool.py
├── README.md
├── requirements.txt
└── LICENSE
```

---

## 📡 Alerting

You can set up simple webhooks or mail notifications for system anomalies.

**Example:**
```bash
sudo python3 onionsite_hardening_tool.py --monitor --alert-webhook "https://yourwebhook.url"
```

---

## 🧩 Future Enhancements

- Full HTML dashboard (local web UI)
- AI-based log anomaly detection
- Integration with SIEM systems (e.g., Wazuh, OpenSearch)

---

## 🤝 Contributing

Pull requests and suggestions are welcome.  
If you find an issue or want to request a feature, open a GitHub Issue.

---

## 🧠 Short Note — How It Helps OnionSite Orchestrator

The **OnionSite Orchestrator** is your deployment brain — it spins up .onion sites and configures Tor + Nginx.  
The **OnionSite Hardening & Monitoring Tool** is the defense layer — it ensures everything stays secure, encrypted, and monitored.

Together they create:

✅ A fully automated .onion deployment pipeline.  
✅ Continuous integrity checks and hardened configurations.  
✅ A self-healing, auditable, and stealth-ready onion infrastructure.

---

## 💬 Author

Developed by **Ashar Dian**  
🚀 _Secure. Harden. Monitor. Evolve._
