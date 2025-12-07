#!/usr/bin/env python3
"""
Enterprise-Grade Advanced Security Module
Implements IDS, Fail2Ban, Intrusion Detection, and Advanced Threat Protection
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Configuration paths
SECURITY_CONFIG_DIR = Path('/etc/onionsite-security')
FAIL2BAN_JAIL_DIR = Path('/etc/fail2ban/jail.d')
IDS_RULES_DIR = Path('/etc/onionsite-security/ids-rules')
AUDIT_LOG = Path('/var/log/onionsite-security/audit.log')
THREAT_INTEL_DB = Path('/var/lib/onionsite-security/threat-intel.json')
ALERT_LOG = Path('/var/log/onionsite-security/alerts.log')

# Ensure directories exist
for d in [SECURITY_CONFIG_DIR, FAIL2BAN_JAIL_DIR, IDS_RULES_DIR, 
          AUDIT_LOG.parent, THREAT_INTEL_DB.parent, ALERT_LOG.parent]:
    try:
        d.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass


def is_root():
    return os.geteuid() == 0


def timestamp():
    return datetime.utcnow().isoformat() + 'Z'


def audit_log(action: str, details: Dict, level: str = 'INFO'):
    """Comprehensive audit logging for all security events"""
    entry = {
        'timestamp': timestamp(),
        'level': level,
        'action': action,
        'details': details,
        'user': os.environ.get('USER', 'unknown'),
        'pid': os.getpid()
    }
    try:
        with open(AUDIT_LOG, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception:
        pass


def run_cmd(cmd: str, capture: bool = True, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Safely execute shell commands"""
    try:
        result = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None, text=True, timeout=timeout
        )
        return result
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, '', 'timeout')
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, '', str(e))


def install_fail2ban():
    """Install and configure Fail2Ban with custom rules"""
    if not is_root():
        raise SystemExit('Root privileges required')
    
    audit_log('fail2ban_install_start', {})
    
    # Install fail2ban
    run_cmd('DEBIAN_FRONTEND=noninteractive apt-get update -qq', capture=True)
    run_cmd('DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban', capture=True)
    
    # Create custom jail for Tor/Nginx
    jail_config = f"""[onionsite-nginx]
enabled = true
port = http,https
filter = onionsite-nginx
logpath = /var/log/nginx/access.log
maxretry = 5
findtime = 600
bantime = 3600
action = %(action_)s

[onionsite-tor]
enabled = true
port = 9050,9051
filter = onionsite-tor
logpath = /var/log/tor/tor.log
maxretry = 10
findtime = 300
bantime = 7200
action = %(action_)s

[onionsite-ssh]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 300
bantime = 86400
action = %(action_)s
"""
    
    jail_file = FAIL2BAN_JAIL_DIR / 'onionsite.conf'
    jail_file.write_text(jail_config)
    
    # Create custom filters
    filter_dir = Path('/etc/fail2ban/filter.d')
    
    nginx_filter = """[Definition]
failregex = ^<HOST>.*"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT).*"(4[0-9]{2}|5[0-9]{2})
            ^<HOST>.*"(GET|POST).*".*".*".*bot.*
            ^<HOST>.*"(GET|POST).*".*".*".*scanner.*
ignoreregex =
"""
    
    (filter_dir / 'onionsite-nginx.conf').write_text(nginx_filter)
    
    tor_filter = """[Definition]
failregex = \[warn\].*<HOST>
            \[err\].*<HOST>
            Connection refused.*<HOST>
ignoreregex =
"""
    
    (filter_dir / 'onionsite-tor.conf').write_text(tor_filter)
    
    # Enable and start fail2ban
    run_cmd('systemctl enable fail2ban', capture=True)
    run_cmd('systemctl restart fail2ban', capture=True)
    
    audit_log('fail2ban_install_complete', {'status': 'success'})
    return True


def setup_intrusion_detection():
    """Setup advanced intrusion detection system"""
    if not is_root():
        raise SystemExit('Root privileges required')
    
    audit_log('ids_setup_start', {})
    
    # Create IDS rules
    ids_rules = """# OnionSite IDS Rules - Enterprise Grade
    
# Detect port scanning
alert tcp any any -> any any (msg:"Port scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000001;)

# Detect SQL injection attempts
alert tcp any any -> 127.0.0.1 8080 (msg:"SQL injection attempt"; content:"union"; content:"select"; nocase; sid:1000002;)

# Detect XSS attempts
alert tcp any any -> 127.0.0.1 8080 (msg:"XSS attempt"; content:"<script"; nocase; sid:1000003;)

# Detect directory traversal
alert tcp any any -> 127.0.0.1 8080 (msg:"Directory traversal attempt"; content:"../"; sid:1000004;)

# Detect command injection
alert tcp any any -> 127.0.0.1 8080 (msg:"Command injection attempt"; content:"|"; content:";"; content:"`"; sid:1000005;)

# Detect excessive requests (DDoS)
alert tcp any any -> 127.0.0.1 8080 (msg:"Potential DDoS"; threshold:type threshold, track by_src, count 100, seconds 10; sid:1000006;)
"""
    
    rules_file = IDS_RULES_DIR / 'onionsite-ids.rules'
    rules_file.write_text(ids_rules)
    
    # Create IDS monitoring script
    ids_monitor = """#!/usr/bin/env python3
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime

LOG_FILE = Path('/var/log/onionsite-security/ids-alerts.log')
THRESHOLD = 5  # Alert threshold

def check_logs():
    # Monitor nginx access logs for suspicious patterns
    patterns = [
        (r'\\b(union|select|insert|delete|drop|exec)\\b', 'SQL_INJECTION'),
        (r'<script|javascript:|onerror=', 'XSS'),
        (r'\\.\\./|\\.\\.\\\\', 'PATH_TRAVERSAL'),
        (r'\\||;|`|\\$\\{', 'COMMAND_INJECTION'),
    ]
    
    try:
        with open('/var/log/nginx/access.log', 'r') as f:
            lines = f.readlines()[-1000:]  # Last 1000 lines
        
        alerts = []
        for line in lines:
            for pattern, threat_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    alerts.append({
                        'timestamp': datetime.utcnow().isoformat(),
                        'threat': threat_type,
                        'log_line': line.strip()
                    })
        
        if alerts:
            with open(LOG_FILE, 'a') as f:
                for alert in alerts:
                    f.write(json.dumps(alert) + '\\n')
            return alerts
    except Exception as e:
        pass
    return []

if __name__ == '__main__':
    alerts = check_logs()
    if alerts:
        print(f"Detected {len(alerts)} threats")
"""
    
    monitor_script = Path('/usr/local/bin/onionsite-ids-monitor.py')
    monitor_script.write_text(ids_monitor)
    monitor_script.chmod(0o755)
    
    # Create systemd service for IDS monitoring
    ids_service = """[Unit]
Description=OnionSite IDS Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/onionsite-ids-monitor.py
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
"""
    
    service_file = Path('/etc/systemd/system/onionsite-ids.service')
    service_file.write_text(ids_service)
    
    # Create timer for periodic checks
    timer_config = """[Unit]
Description=OnionSite IDS Scanner Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
"""
    
    timer_file = Path('/etc/systemd/system/onionsite-ids.timer')
    timer_file.write_text(timer_config)
    
    run_cmd('systemctl daemon-reload', capture=True)
    run_cmd('systemctl enable --now onionsite-ids.timer', capture=True)
    
    audit_log('ids_setup_complete', {'status': 'success'})
    return True


def setup_rate_limiting():
    """Configure advanced rate limiting for DDoS protection"""
    if not is_root():
        raise SystemExit('Root privileges required')
    
    audit_log('rate_limiting_setup', {})
    
    # Create nginx rate limiting configuration
    rate_limit_conf = """# Rate limiting zones
limit_req_zone $binary_remote_addr zone=general_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=strict_limit:10m rate=2r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Connection limiting
limit_conn conn_limit 10;
"""
    
    rate_limit_file = Path('/etc/nginx/snippets/rate-limiting.conf')
    rate_limit_file.write_text(rate_limit_conf)
    
    # Apply to nginx sites
    nginx_site_conf = Path('/etc/nginx/sites-available/onion_site')
    if nginx_site_conf.exists():
        content = nginx_site_conf.read_text()
        if 'rate-limiting.conf' not in content:
            content = content.replace(
                'server {',
                'server {\n    include /etc/nginx/snippets/rate-limiting.conf;'
            )
            nginx_site_conf.write_text(content)
    
    run_cmd('nginx -t && systemctl reload nginx', capture=True)
    
    audit_log('rate_limiting_complete', {'status': 'success'})
    return True


def setup_apparmor_profiles():
    """Create and enforce AppArmor profiles for Tor and Nginx"""
    if not is_root():
        raise SystemExit('Root privileges required')
    
    audit_log('apparmor_setup', {})
    
    # Check if AppArmor is available
    if not shutil.which('apparmor_status'):
        run_cmd('DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor apparmor-utils', capture=True)
    
    # Create AppArmor profile for Tor
    tor_profile = """#include <tunables/global>

/usr/bin/tor {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  /etc/tor/** r,
  /var/lib/tor/** rw,
  /var/log/tor/** w,
  /var/run/tor/** rw,
  /usr/bin/tor ix,
  /usr/lib/** mr,
  
  deny /proc/*/mem r,
  deny /sys/kernel/** r,
  
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability dac_override,
}
"""
    
    profile_dir = Path('/etc/apparmor.d')
    (profile_dir / 'usr.bin.tor').write_text(tor_profile)
    
    # Create AppArmor profile for Nginx
    nginx_profile = """#include <tunables/global>

/usr/sbin/nginx {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/web-data>

  /etc/nginx/** r,
  /var/www/** r,
  /var/log/nginx/** w,
  /var/run/nginx.pid w,
  /var/cache/nginx/** rw,
  /usr/sbin/nginx ix,
  /usr/lib/** mr,
  
  deny /proc/*/mem r,
  deny /sys/kernel/** r,
  
  capability net_bind_service,
  capability setuid,
  capability setgid,
}
"""
    
    (profile_dir / 'usr.sbin.nginx').write_text(nginx_profile)
    
    # Enforce profiles
    run_cmd('apparmor_parser -r /etc/apparmor.d/usr.bin.tor', capture=True)
    run_cmd('apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx', capture=True)
    
    audit_log('apparmor_complete', {'status': 'success'})
    return True


def setup_advanced_firewall():
    """Configure advanced firewall with nftables"""
    if not is_root():
        raise SystemExit('Root privileges required')
    
    audit_log('advanced_firewall_setup', {})
    
    # Install nftables if not present
    if not shutil.which('nft'):
        run_cmd('DEBIAN_FRONTEND=noninteractive apt-get install -y nftables', capture=True)
    
    # Create comprehensive nftables ruleset
    nft_rules = """#!/usr/sbin/nft -f
# Flush existing rules
flush ruleset

# Define variables
define SSH_PORT = 22
define TOR_CONTROL = 9051
define TOR_SOCKS = 9050

# Create tables
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Accept loopback
        iif lo accept
        
        # Accept established/related connections
        ct state established,related accept
        
        # Rate limiting for SSH
        limit rate 5/minute burst 10 packets accept tcp dport $SSH_PORT
        
        # SSH
        tcp dport $SSH_PORT accept
        
        # Drop invalid packets
        ct state invalid drop
        
        # Log and drop everything else
        log prefix "DROPPED: " drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# IPv4 specific rules
table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Anti-DDoS: Limit connections per IP
        ct state new limit rate 10/minute burst 20 accept
        
        # Drop fragmented packets (potential attack)
        ip frag-off & 0x1fff != 0 drop
    }
}
"""
    
    rules_file = Path('/etc/nftables/onionsite-security.nft')
    rules_file.write_text(nft_rules)
    rules_file.chmod(0o644)
    
    # Enable nftables
    run_cmd('systemctl enable nftables', capture=True)
    run_cmd('nft -f /etc/nftables/onionsite-security.nft', capture=True)
    run_cmd('systemctl start nftables', capture=True)
    
    audit_log('advanced_firewall_complete', {'status': 'success'})
    return True


def threat_intelligence_update():
    """Update threat intelligence database"""
    # This would typically connect to threat intel feeds
    # For now, we maintain a local database
    
    threats = {
        'known_malicious_ips': [],
        'known_bad_user_agents': [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zmap',
            'scanner', 'bot', 'crawler', 'spider'
        ],
        'suspicious_patterns': [
            r'\.\./', r'\.\.\\', r'<script', r'union.*select',
            r'exec\(', r'eval\(', r'system\(', r'passthru\('
        ]
    }
    
    try:
        THREAT_INTEL_DB.write_text(json.dumps(threats, indent=2))
        audit_log('threat_intel_update', {'status': 'success'})
    except Exception as e:
        audit_log('threat_intel_update', {'status': 'failed', 'error': str(e)}, 'ERROR')
    
    return threats


def check_security_status() -> Dict:
    """Comprehensive security status check"""
    status = {
        'fail2ban': False,
        'ids': False,
        'apparmor': False,
        'firewall': False,
        'rate_limiting': False,
        'threats_detected': 0
    }
    
    # Check Fail2Ban
    result = run_cmd('systemctl is-active fail2ban', capture=True)
    status['fail2ban'] = result.returncode == 0
    
    # Check IDS
    result = run_cmd('systemctl is-active onionsite-ids.timer', capture=True)
    status['ids'] = result.returncode == 0
    
    # Check AppArmor
    result = run_cmd('apparmor_status 2>/dev/null | grep -q "enforce"', capture=True)
    status['apparmor'] = result.returncode == 0
    
    # Check firewall
    result = run_cmd('systemctl is-active nftables', capture=True)
    status['firewall'] = result.returncode == 0
    
    # Check rate limiting
    rate_limit_file = Path('/etc/nginx/snippets/rate-limiting.conf')
    status['rate_limiting'] = rate_limit_file.exists()
    
    # Count recent threats
    ids_log = Path('/var/log/onionsite-security/ids-alerts.log')
    if ids_log.exists():
        try:
            with open(ids_log, 'r') as f:
                lines = f.readlines()
                # Count threats in last 24 hours
                cutoff = datetime.utcnow() - timedelta(hours=24)
                recent_threats = 0
                for line in lines[-100:]:  # Check last 100 lines
                    try:
                        alert = json.loads(line)
                        alert_time = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                        if alert_time.replace(tzinfo=None) > cutoff:
                            recent_threats += 1
                    except:
                        pass
                status['threats_detected'] = recent_threats
        except:
            pass
    
    return status


def apply_all_security():
    """Apply all security measures"""
    if not is_root():
        raise SystemExit('Root privileges required')
    
    audit_log('security_apply_start', {})
    
    results = {
        'fail2ban': False,
        'ids': False,
        'apparmor': False,
        'firewall': False,
        'rate_limiting': False,
        'threat_intel': False
    }
    
    try:
        results['fail2ban'] = install_fail2ban()
    except Exception as e:
        audit_log('fail2ban_failed', {'error': str(e)}, 'ERROR')
    
    try:
        results['ids'] = setup_intrusion_detection()
    except Exception as e:
        audit_log('ids_failed', {'error': str(e)}, 'ERROR')
    
    try:
        results['apparmor'] = setup_apparmor_profiles()
    except Exception as e:
        audit_log('apparmor_failed', {'error': str(e)}, 'ERROR')
    
    try:
        results['firewall'] = setup_advanced_firewall()
    except Exception as e:
        audit_log('firewall_failed', {'error': str(e)}, 'ERROR')
    
    try:
        results['rate_limiting'] = setup_rate_limiting()
    except Exception as e:
        audit_log('rate_limiting_failed', {'error': str(e)}, 'ERROR')
    
    try:
        threat_intelligence_update()
        results['threat_intel'] = True
    except Exception as e:
        audit_log('threat_intel_failed', {'error': str(e)}, 'ERROR')
    
    audit_log('security_apply_complete', results)
    return results


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Security Module')
    parser.add_argument('--apply', action='store_true', help='Apply all security measures')
    parser.add_argument('--status', action='store_true', help='Check security status')
    parser.add_argument('--fail2ban', action='store_true', help='Setup Fail2Ban')
    parser.add_argument('--ids', action='store_true', help='Setup IDS')
    parser.add_argument('--apparmor', action='store_true', help='Setup AppArmor')
    parser.add_argument('--firewall', action='store_true', help='Setup advanced firewall')
    parser.add_argument('--rate-limit', action='store_true', help='Setup rate limiting')
    
    args = parser.parse_args()
    
    if args.apply:
        results = apply_all_security()
        print(json.dumps(results, indent=2))
    elif args.status:
        status = check_security_status()
        print(json.dumps(status, indent=2))
    elif args.fail2ban:
        install_fail2ban()
    elif args.ids:
        setup_intrusion_detection()
    elif args.apparmor:
        setup_apparmor_profiles()
    elif args.firewall:
        setup_advanced_firewall()
    elif args.rate_limit:
        setup_rate_limiting()
    else:
        parser.print_help()

