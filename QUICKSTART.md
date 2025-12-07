# 🚀 Quick Start Guide - Enterprise-Grade OnionSite Orchestrator

## Installation (5 minutes)

```bash
# 1. Clone repository
git clone <your-repo-url>
cd OnionSite-Orchestrator-main

# 2. Run installer
sudo bash install_advanced.sh

# 3. Deploy complete stack
sudo python3 unified_orchestrator.py --deploy
```

That's it! Your enterprise-grade OnionSite is now deployed with:
- ✅ Full security hardening
- ✅ Automated backups
- ✅ Real-time monitoring
- ✅ Security scanning
- ✅ All services configured

## Get Your Onion Address

```bash
sudo /usr/local/bin/onionsite-orchestrator.sh --show
```

## Check Status

```bash
sudo python3 unified_orchestrator.py --status
```

## View Dashboard

```bash
cat /var/lib/onionsite-monitoring/dashboard.json | jq
```

## Common Commands

### Backup
```bash
sudo python3 /usr/local/bin/automated_backup_rotation.py --backup --encrypt
```

### Security Scan
```bash
sudo python3 /usr/local/bin/security_scanner.py --scan --report
```

### Rotate Keys
```bash
sudo python3 /usr/local/bin/automated_backup_rotation.py --rotate-keys --backup-first --encrypt
```

### View Logs
```bash
# Main logs
sudo tail -f /var/log/onionsite-orchestrator/unified.log

# Security alerts
sudo tail -f /var/log/onionsite-security/alerts.log

# Monitoring
sudo tail -f /var/log/onionsite-monitoring/metrics.log
```

## Configuration

Edit configuration:
```bash
sudo nano /etc/onionsite-orchestrator/config.json
```

## Troubleshooting

If something goes wrong:
```bash
# Self-heal
sudo /usr/local/bin/onionsite-orchestrator.sh --self-heal

# Check services
sudo systemctl status tor nginx fail2ban

# View recent errors
sudo journalctl -xe
```

## Next Steps

1. **Configure Alerts**: Edit config.json and add webhook/email
2. **Set GPG Key**: For encrypted backups
3. **Review Security Scan**: Run initial scan and address findings
4. **Test Backups**: Verify backup and restore procedures

## Support

- Full documentation: See README_ADVANCED.md
- Check logs: /var/log/onionsite-*/
- Status report: `sudo python3 unified_orchestrator.py --status`

---

**🛡️ Your OnionSite is now enterprise-grade secure! 🛡️**

