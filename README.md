# 🛡️ OnionSite-Orchestrator - Enterprise Edition

### Advanced Tor Hidden Service Deployment and Security Management System

**OnionSite-Orchestrator** is an **enterprise-grade**, fully automated tool designed to deploy, secure, and manage Tor Hidden Services (Onion websites) on **Debian-based Linux systems**.  

It provides both **basic deployment** capabilities and **advanced security features**, including intrusion detection, automated backups, real-time monitoring, and comprehensive security scanning.

---

## 🚀 Features

### Core Features (Basic Edition)
✅ **One-command setup** — fully automated installation and configuration  
✅ **Automatic Tor + Nginx orchestration**  
✅ **Self-healing** — detects and fixes Tor/Nginx misconfigurations automatically  
✅ **Secure defaults** — serves your site only via localhost and Tor  
✅ **Firewall integration (UFW)** — blocks all inbound traffic except SSH  
✅ **Onion hostname generation** — no manual configuration required  
✅ **Automatic restart and recovery** if Tor or Nginx stop unexpectedly  
✅ **Detailed logging** — view full logs in `/var/log/onionsite-orchestrator.log`  
✅ **Custom webroot detection and repair**  
✅ **Works out of the box on Debian 11+, Parrot OS, and Ubuntu 22.04+**

### Advanced Security Features (Enterprise Edition)
✅ **Advanced Intrusion Detection System (IDS)** — pattern-based attack detection  
✅ **Automated Fail2Ban** — custom jails for Tor, Nginx, and SSH  
✅ **AppArmor/SELinux profiles** — mandatory access control  
✅ **Advanced firewall** — nftables with DDoS protection and rate limiting  
✅ **Automated backup and key rotation** — GPG-encrypted backups with rotation policies  
✅ **Comprehensive real-time monitoring** — anomaly detection and health scoring  
✅ **Automated security scanning** — vulnerability assessment and risk scoring  
✅ **Threat intelligence integration** — local threat database  
✅ **Full audit logging** — complete compliance tracking  
✅ **Zero-trust architecture** — defense in depth principles

---

## 🧩 Requirements

- Debian / Ubuntu / Parrot OS (Tested on Debian)
- Root or `sudo` privileges  
- Active network connection  
- `apt`, `systemd`, and `bash` available (default on Debian-based distros)
- Python 3.6+ (for advanced features)

---

## ⚙️ Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/<your-username>/onionsite-orchestrator.git
cd OnionSite-Orchestrator-main

# Make scripts executable
chmod +x *.sh *.py

# Install all components
sudo bash install_advanced.sh

# Deploy complete enterprise-grade stack
sudo python3 unified_orchestrator.py --deploy
```

This will:
1. Install all dependencies
2. Deploy base OnionSite
3. Apply all security hardening
4. Set up automated backups
5. Configure monitoring
6. Run initial security scan

### Basic Installation (Bash Script Only)

If you only need the basic deployment:

```bash
# Clone or download
git clone https://github.com/<your-username>/onionsite-orchestrator.git
cd onionsite-orchestrator

# Make executable
chmod +x onionsite-orchestrator.sh

# Install base system
sudo ./onionsite-orchestrator.sh --install
```

This installs the orchestrator globally to:
```
/usr/local/bin/onionsite-orchestrator.sh
```

### Manual Installation (Step by Step)

```bash
# 1. Install base OnionSite
sudo ./onionsite-orchestrator.sh --install

# 2. Apply security hardening
sudo python3 advanced_security_module.py --apply

# 3. Setup automated backups
sudo python3 automated_backup_rotation.py --auto

# 4. Start monitoring
sudo python3 comprehensive_monitoring.py --monitor --webhook "https://your-webhook.url" --email "admin@example.com"

# 5. Run security scan
sudo python3 security_scanner.py --scan --report

# 6. Install all automated services
sudo python3 unified_orchestrator.py --install-services
```

---

## 🧠 Usage

### 🏗️ Basic Usage (Bash Script)

#### Initial Setup
```bash
sudo onionsite-orchestrator.sh --install
```

This command will:
* Install all required packages (`tor`, `nginx`, `ufw`, `openssl`, etc.)
* Configure a secure Nginx instance on localhost
* Set up a hidden Tor service at `/var/lib/tor/onion_service`
* Auto-create a sample website at `/var/www/onion_site`
* Print your new `.onion` address at the end

#### View Onion Address
```bash
sudo onionsite-orchestrator.sh --show
```

#### Self-Heal / Repair Service
If your Onion site fails to load in the Tor browser:
```bash
sudo onionsite-orchestrator.sh --self-heal
```

This feature automatically:
* Checks Tor logs and restarts it if needed
* Validates Tor control and SOCKS5 ports (9050, 9051)
* Repairs `/etc/tor/torrc` configuration
* Verifies Nginx binding to `127.0.0.1:8080`
* Regenerates hidden service if corrupted
* Reconfirms onion hostname availability

#### Firewall Configuration
```bash
sudo onionsite-orchestrator.sh --firewall
```

This resets and configures UFW with:
* `deny incoming`
* `allow outgoing`
* `allow ssh`

#### Service Status
```bash
sudo onionsite-orchestrator.sh --status
```

Shows:
* Tor/Nginx running state
* Active `.onion` address
* Listening ports
* UFW firewall rules
* Log file path

#### Backup
```bash
sudo onionsite-orchestrator.sh --backup
```

#### Rotate Keys
```bash
sudo onionsite-orchestrator.sh --rotate-keys
```

#### Uninstall
```bash
sudo onionsite-orchestrator.sh --remove
```

---

### 🛡️ Advanced Usage (Python Modules)

#### Deploy Complete Stack
```bash
sudo python3 unified_orchestrator.py --deploy
```

This single command:
1. Deploys base OnionSite
2. Applies all security measures
3. Sets up automated backups
4. Configures monitoring
5. Runs initial security scan

#### Status Report
```bash
sudo python3 unified_orchestrator.py --status
```

#### Security Module
```bash
# Apply all security
sudo python3 advanced_security_module.py --apply

# Check security status
sudo python3 advanced_security_module.py --status

# Individual components
sudo python3 advanced_security_module.py --fail2ban
sudo python3 advanced_security_module.py --ids
sudo python3 advanced_security_module.py --apparmor
sudo python3 advanced_security_module.py --firewall
sudo python3 advanced_security_module.py --rate-limit
```

#### Backup System
```bash
# Full backup
sudo python3 automated_backup_rotation.py --backup --encrypt --gpg-recipient "your@email.com"

# Backup keys only
sudo python3 automated_backup_rotation.py --backup-keys --encrypt

# Rotate keys
sudo python3 automated_backup_rotation.py --rotate-keys --backup-first --encrypt

# Restore from backup
sudo python3 automated_backup_rotation.py --restore /path/to/backup.tar.gz --restore-type keys
```

#### Monitoring
```bash
# Start monitoring (foreground)
sudo python3 comprehensive_monitoring.py --monitor --interval 60 --webhook "https://webhook.url" --email "admin@example.com"

# Get current metrics
sudo python3 comprehensive_monitoring.py --metrics

# View dashboard
sudo python3 comprehensive_monitoring.py --dashboard
```

#### Security Scanner
```bash
# Comprehensive scan
sudo python3 security_scanner.py --scan --report

# Port scan only
sudo python3 security_scanner.py --ports

# Config scan only
sudo python3 security_scanner.py --config

# Nikto scan
sudo python3 security_scanner.py --nikto --target 127.0.0.1:8080
```

---

## 🪪 Example Output

### Basic Installation
```
[2025-11-02T13:00:16Z] [INFO] Tor: active
[2025-11-02T13:00:16Z] [INFO] nginx: active
[2025-11-02T13:00:16Z] [INFO] Onion hostname created: http://evk4qkbycx2gx5oxthrjynsjziqttqnne5xo6v6zanhtlid.onion
[2025-11-02T13:00:16Z] [INFO] Web server reachable at 127.0.0.1:8080
[2025-11-02T13:00:16Z] [INFO] Access your onion site using Tor Browser:
       http://evk4qkbycx2gx5oxthrjynsjziqttqnne5xo6v6zanhtlid.onion
```

### Advanced Deployment
```
==========================================
DEPLOYING ENTERPRISE-GRADE ONIONSITE STACK
==========================================
Step 1: Deploying base OnionSite...
Step 2: Applying security hardening...
Step 3: Setting up automated backups...
Step 4: Setting up monitoring...
Step 5: Running initial security scan...
==========================================
DEPLOYMENT COMPLETE
==========================================
```

---

## 📊 Monitoring Dashboard

Access dashboard data:
```bash
cat /var/lib/onionsite-monitoring/dashboard.json | jq
```

Dashboard includes:
- Real-time system metrics
- Service health status
- Detected anomalies
- Overall health score (0-100)
- Recent alerts

---

## 🔒 Security Notes

### Basic Security
* The site only listens on **localhost (127.0.0.1)** for maximum isolation.
* **No clearnet access** — it's only available over Tor.
* The script applies **best practices** for Tor hidden service deployment:
  * Disables directory indexing
  * Denies framing (anti-clickjacking)
  * Enforces MIME type consistency
  * Uses restrictive UFW rules

### Advanced Security
* **Defense in Depth**: Multiple security layers (network, application, process, service, monitoring)
* **Zero Trust**: Verify all connections and operations
* **Least Privilege**: Minimal required permissions
* **Encryption**: GPG-encrypted backups, secure key storage
* **Audit Logging**: Complete audit trail for compliance
* **Automated Response**: Self-healing and automatic threat response

---

## 🔐 Security Best Practices

### 1. **Key Management**
- Always encrypt backups with GPG
- Rotate keys regularly (every 90 days recommended)
- Store encrypted backups off-site
- Use hardware security modules (HSM) for production

### 2. **Monitoring**
- Set up webhook alerts for critical events
- Configure email notifications
- Review dashboard daily
- Set up external monitoring (e.g., UptimeRobot)

### 3. **Backups**
- Automated daily backups
- Encrypt all sensitive backups
- Test restore procedures monthly
- Keep multiple backup generations

### 4. **Scanning**
- Run security scans weekly
- Review and act on findings
- Keep dependencies updated
- Monitor for new CVEs

### 5. **Access Control**
- Use SSH keys, disable password auth
- Implement fail2ban for SSH
- Use VPN for administrative access
- Regular security audits

---

## 📁 Directory Structure

```
/var/
├── backups/onionsite/          # Encrypted backups
│   ├── keys/                   # Hidden service keys
│   ├── configs/                # Configuration backups
│   └── encrypted/              # GPG encrypted backups
├── lib/
│   ├── onionsite-monitoring/  # Monitoring data
│   │   ├── metrics.json        # Historical metrics
│   │   └── dashboard.json     # Dashboard data
│   └── onionsite-security/     # Security data
│       ├── scans/              # Scan results
│       ├── ids-rules/           # IDS rules
│       └── threat-intel.json    # Threat intelligence
└── log/
    ├── onionsite-orchestrator/ # Main logs
    │   └── unified.log         # Unified orchestrator log
    ├── onionsite-security/     # Security logs
    │   ├── audit.log           # Audit trail
    │   ├── alerts.log          # Security alerts
    │   └── ids-alerts.log      # IDS alerts
    ├── onionsite-monitoring/    # Monitoring logs
    │   ├── metrics.log         # Metrics log
    │   └── alerts.log          # Monitoring alerts
    └── onionsite-backup/        # Backup logs
        └── backup.log           # Backup operations
```

---

## 🔧 Configuration

Edit configuration:
```bash
sudo nano /etc/onionsite-orchestrator/config.json
```

Example configuration:
```json
{
  "security": {
    "fail2ban": true,
    "ids": true,
    "apparmor": true,
    "firewall": true,
    "rate_limiting": true
  },
  "backup": {
    "enabled": true,
    "encrypt": true,
    "gpg_recipient": "your@email.com",
    "auto_rotate_keys": false,
    "rotation_days": 90
  },
  "monitoring": {
    "enabled": true,
    "interval": 60,
    "webhook": "https://your-webhook.url",
    "email": "admin@example.com"
  },
  "scanning": {
    "auto_scan": true,
    "scan_interval_hours": 24
  }
}
```

---

## 🚨 Alerting

### Webhook Integration

Example webhook payload:
```json
{
  "text": "[CRITICAL] Service tor is not active",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Email Alerts

Configure mail:
```bash
sudo apt-get install mailutils
sudo nano /etc/ssmtp/ssmtp.conf
```

### Syslog Integration

All alerts are logged to syslog:
```bash
journalctl -u onionsite-monitoring -f
```

---

## 🧾 Logs & Diagnostics

### Main Logs
All actions are logged to:
```
/var/log/onionsite-orchestrator.log          # Basic orchestrator
/var/log/onionsite-orchestrator/unified.log  # Unified orchestrator
```

### Security Logs
```
/var/log/onionsite-security/audit.log       # Audit trail
/var/log/onionsite-security/alerts.log       # Security alerts
/var/log/onionsite-security/ids-alerts.log   # IDS alerts
```

### Monitoring Logs
```
/var/log/onionsite-monitoring/metrics.log    # Metrics
/var/log/onionsite-monitoring/alerts.log     # Monitoring alerts
```

### Backup Logs
```
/var/log/onionsite-backup/backup.log         # Backup operations
```

### View Logs
```bash
# Real-time main log
sudo tail -f /var/log/onionsite-orchestrator.log

# Real-time unified log
sudo tail -f /var/log/onionsite-orchestrator/unified.log

# Security alerts
sudo tail -f /var/log/onionsite-security/alerts.log

# Monitoring
sudo tail -f /var/log/onionsite-monitoring/metrics.log
```

---

## 💬 Troubleshooting

### Basic Issues

| Problem                       | Solution                                         |
| ----------------------------- | ------------------------------------------------ |
| `.onion` site not loading     | Run `sudo onionsite-orchestrator.sh --self-heal` |
| Tor service stops             | `sudo systemctl restart tor`                     |
| No `.onion` address generated | Check `/var/lib/tor/onion_service/hostname`      |
| Nginx fails to reload         | Run `nginx -t` to test config                    |
| Firewall blocking Tor         | Run `sudo onionsite-orchestrator.sh --firewall`  |

### Advanced Issues

#### Services Not Starting
```bash
# Check service status
sudo systemctl status tor nginx fail2ban

# Check logs
sudo journalctl -u tor -n 50
sudo journalctl -u nginx -n 50
```

#### Backup Issues
```bash
# Check backup logs
sudo tail -f /var/log/onionsite-backup/backup.log

# Verify GPG
gpg --list-keys
```

#### Monitoring Issues
```bash
# Check monitoring service
sudo systemctl status onionsite-monitoring

# View metrics
sudo python3 comprehensive_monitoring.py --metrics
```

#### Security Scan Issues
```bash
# Run scan with verbose output
sudo python3 security_scanner.py --scan --report

# Check scan results
ls -la /var/lib/onionsite-security/scans/
```

---

## 📈 Performance Tuning

### Monitoring Interval
Adjust in config or command:
```bash
sudo python3 comprehensive_monitoring.py --monitor --interval 120
```

### Backup Schedule
Edit timer:
```bash
sudo systemctl edit onionsite-backup.timer
```

### Scan Frequency
Edit timer:
```bash
sudo systemctl edit onionsite-scanner.timer
```

---

## 🛡️ Compliance

This system implements:
- **Defense in Depth**: Multiple security layers
- **Zero Trust**: Verify everything
- **Least Privilege**: Minimal required permissions
- **Audit Logging**: Complete audit trail
- **Encryption**: At rest and in transit
- **Automated Response**: Self-healing capabilities

---

## 🔄 Updates and Maintenance

### Update System
```bash
sudo apt-get update && sudo apt-get upgrade
```

### Update OnionSite Tools
```bash
cd /path/to/OnionSite-Orchestrator
git pull
sudo python3 unified_orchestrator.py --deploy
```

### Rotate Keys
```bash
sudo python3 automated_backup_rotation.py --rotate-keys --backup-first --encrypt
```

---

## 📚 Additional Resources

- [Tor Project Documentation](https://www.torproject.org/docs/)
- [Nginx Security Guide](https://nginx.org/en/docs/http/ngx_http_core_module.html)
- [Fail2Ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [AppArmor Documentation](https://apparmor.net/documentation/)

---

## 🤝 Contributing

1. Fork this repo
2. Create a new feature branch
3. Submit a PR with detailed description

Bug reports and suggestions are always welcome!

---

## 🧾 License

This project is released under the **MIT License**.  
See `LICENSE` for more details.

---

## 👨‍💻 Author

**OnionSite-Orchestrator** by Ashar Dian  
Built for privacy enthusiasts, researchers, and developers who value secure web hosting over Tor.

**Enterprise Edition** enhancements provide advanced security and automation.

---

## ⚠️ Disclaimer

This tool is for legitimate security research and privacy protection. Users are responsible for compliance with all applicable laws and regulations.

---

**🛡️ Secure. Automated. Enterprise-Grade. 🛡️**
