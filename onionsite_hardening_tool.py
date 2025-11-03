#!/usr/bin/env python3

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Config locations
BACKUP_DIR = Path('/var/backups/onionsite-hardener')
REPORT_DIR = Path('/var/log/onionsite-hardener')
REPORT_FILE = REPORT_DIR / 'report.json'
LOG_FILE = REPORT_DIR / 'hardener.log'
SERVICE_UNIT_PATH = Path('/etc/systemd/system/onionsite-hardener-monitor.service')

# Ensure directories exist where possible
for d in (BACKUP_DIR, REPORT_DIR):
    try:
        d.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # Will log later if we can't write
        pass


def is_root():
    return os.geteuid() == 0


def timestamp():
    return datetime.utcnow().isoformat() + 'Z'


def safe_log(message):
    """Append a line to the tool log if writable; otherwise print to stderr."""
    line = f"{timestamp()} - {message}\n"
    try:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(line)
    except Exception:
        # fallback
        try:
            sys.stderr.write(line)
        except Exception:
            pass


def run(cmd, capture=False, timeout=None):
    """
    Run a shell command in a safe manner.
    Always returns a subprocess.CompletedProcess-like object with (args, returncode, stdout, stderr).
    Uses shell=True for convenience but carefully accepts pre-quoted inputs (caller should use shlex.quote).
    """
    try:
        if capture:
            cp = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        else:
            # capture by default to avoid unexpected stdout/stderr spamming when callers expect capture
            cp = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return cp
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(args=cmd, returncode=124, stdout='', stderr='timeout')
    except Exception as e:
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout='', stderr=str(e))


def safe_backup(path: Path):
    """Copy path to BACKUP_DIR with timestamp; return destination path or None on failure."""
    try:
        if not path.exists():
            return None
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        dest = BACKUP_DIR / f"{path.name}.{ts}.bak"
        shutil.copy2(path, dest)
        safe_log(f"backup {path} -> {dest}")
        return dest
    except Exception as e:
        safe_log(f"backup_failed {path} {e}")
        return None


def detect_hidden_service():
    """Return HiddenServiceDir Path if present in /etc/tor/torrc, else None."""
    torrc = Path('/etc/tor/torrc')
    if not torrc.exists():
        return None
    try:
        txt = torrc.read_text(errors='ignore')
    except Exception as e:
        safe_log(f"read_torrc_failed {e}")
        return None
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('HiddenServiceDir'):
            parts = line.split(None, 1)
            if len(parts) == 2:
                hs = parts[1].strip().strip('"').strip("'")
                return Path(hs)
    return None


def detect_hidden_service_port():
    """
    Return the first HiddenServicePort target (host:port) string, e.g. '127.0.0.1:8080'.
    If missing, return None.
    """
    torrc = Path('/etc/tor/torrc')
    if not torrc.exists():
        return None
    try:
        txt = torrc.read_text(errors='ignore')
    except Exception as e:
        safe_log(f"read_torrc_failed {e}")
        return None
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('HiddenServicePort'):
            parts = line.split()
            # HiddenServicePort <virt_port> <target_host>:<target_port>
            if len(parts) >= 3:
                target = parts[2].strip().strip('"').strip("'")
                return target
    return None


def check_tor():
    findings = []
    torrc = Path('/etc/tor/torrc')
    if torrc.exists():
        findings.append({'name': 'torrc_exists', 'ok': True, 'detail': '/etc/tor/torrc present'})
        try:
            txt = torrc.read_text(errors='ignore')
        except Exception as e:
            findings.append({'name': 'torrc_readable', 'ok': False, 'detail': str(e)})
            return findings
        if 'HiddenServiceDir' in txt and 'HiddenServicePort' in txt:
            findings.append({'name': 'torrc_hidden_service', 'ok': True, 'detail': 'HiddenService configured'})
            hs = detect_hidden_service()
            if hs:
                findings.append({'name': 'hidden_service_dir', 'ok': hs.exists(), 'detail': str(hs)})
                priv = hs / 'private_key'
                findings.append({'name': 'hidden_service_key', 'ok': priv.exists(), 'detail': str(priv) if priv.exists() else 'missing'})
                if priv.exists():
                    try:
                        m = oct(priv.stat().st_mode & 0o777)
                        findings.append({'name': 'hidden_service_key_perms', 'ok': (priv.stat().st_mode & 0o777) <= 0o700, 'detail': m})
                    except Exception as e:
                        findings.append({'name': 'hidden_service_key_perms', 'ok': False, 'detail': str(e)})
        else:
            findings.append({'name': 'torrc_hidden_service', 'ok': False, 'detail': 'HiddenService not found in torrc'})
    else:
        findings.append({'name': 'torrc_exists', 'ok': False, 'detail': '/etc/tor/torrc missing'})

    s = run('systemctl is-active tor', capture=True)
    findings.append({'name': 'tor_systemd_active', 'ok': s.stdout.strip() == 'active', 'detail': s.stdout.strip()})
    return findings


def check_nginx():
    findings = []
    s = run('systemctl is-active nginx', capture=True)
    findings.append({'name': 'nginx_active', 'ok': s.stdout.strip() == 'active', 'detail': s.stdout.strip()})
    # Check listening sockets for nginx process
    ss = run("ss -ltnp | grep -E 'nginx' || true", capture=True)
    listen_ok = False
    hs_target = detect_hidden_service_port()
    if hs_target and '127.0.0.1' in hs_target:
        # If HiddenServicePort maps to 127.0.0.1:PORT, ensure nginx listens there
        listen_ok = hs_target in ss.stdout
    else:
        listen_ok = '127.0.0.1' in ss.stdout or 'localhost' in ss.stdout
    findings.append({'name': 'nginx_listen_loopback', 'ok': listen_ok, 'detail': ss.stdout.strip()})
    # Check common conf existence
    confs = []
    for p in ['/etc/nginx/nginx.conf', '/etc/nginx/sites-enabled']:
        path = Path(p)
        if path.exists():
            confs.append(p)
    findings.append({'name': 'nginx_conf_found', 'ok': len(confs) > 0, 'detail': ','.join(confs)})
    # Check for server_tokens off usage in configs
    snippets = []
    try:
        for f in Path('/etc/nginx').rglob('*.conf'):
            try:
                txt = f.read_text(errors='ignore')
            except Exception:
                continue
            if 'server_tokens off' in txt:
                snippets.append(str(f))
    except Exception:
        pass
    findings.append({'name': 'nginx_hardening_snippets', 'ok': len(snippets) > 0, 'detail': ','.join(snippets)})
    return findings


def check_system():
    findings = []
    s = run('dpkg -l unattended-upgrades 2>/dev/null | grep ^ii || true', capture=True)
    findings.append({'name': 'unattended_upgrades', 'ok': 'ii' in s.stdout, 'detail': s.stdout.strip()})
    ufw = run('which ufw >/dev/null 2>&1 && ufw status verbose || true', capture=True)
    nft = run('which nft >/dev/null 2>&1 && nft list ruleset || true', capture=True)
    findings.append({'name': 'ufw_installed', 'ok': 'Status:' in ufw.stdout, 'detail': ufw.stdout.strip()})
    findings.append({'name': 'nft_present', 'ok': 'table' in nft.stdout.lower(), 'detail': nft.stdout.strip()})
    s2 = run('systemctl is-active fail2ban', capture=True)
    findings.append({'name': 'fail2ban_active', 'ok': 'active' in s2.stdout, 'detail': s2.stdout.strip()})
    return findings


def scan_ports():
    s = run("ss -ltnp", capture=True)
    return s.stdout


def generate_nginx_snippet():
    return '''# Onionsite hardening snippet
server_tokens off;
client_max_body_size 5M;
client_body_timeout 10s;
send_timeout 5s;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Download-Options "noopen" always;
# Tune CSP per site:
# add_header Content-Security-Policy "default-src 'self'" always;
'''


def apply_hardening(enable_waf=False, setup_firewall=False, backup_key=False, encrypt_key=False, gpg_recipient=None):
    if not is_root():
        raise SystemExit('apply requires root privileges')
    actions = []
    torrc = Path('/etc/tor/torrc')
    if torrc.exists():
        b = safe_backup(torrc)
        actions.append({'action': 'backup_file', 'file': str(torrc), 'backup': str(b) if b else None})
        hs = detect_hidden_service()
        if hs and hs.exists():
            try:
                prev = oct(hs.stat().st_mode & 0o777)
                hs.chmod(0o700)
                actions.append({'action': 'chmod_hidden_service', 'path': str(hs), 'prev_perms': prev, 'now': '700'})
            except Exception as e:
                actions.append({'action': 'chmod_hidden_service_failed', 'err': str(e)})
            priv = hs / 'private_key'
            if priv.exists() and backup_key:
                b2 = safe_backup(priv)
                actions.append({'action': 'backup_hidden_service_key', 'file': str(priv), 'backup': str(b2) if b2 else None})
                if encrypt_key:
                    enc = BACKUP_DIR / f"private_key.{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.gpg"
                    try:
                        if gpg_recipient and shutil.which('gpg'):
                            # Quote paths/recipients properly
                            cmd = f"gpg --yes --batch -o {shlex.quote(str(enc))} --encrypt -r {shlex.quote(gpg_recipient)} {shlex.quote(str(priv))}"
                            run(cmd, capture=True)
                        elif shutil.which('gpg'):
                            cmd = f"gpg --yes --batch --symmetric -o {shlex.quote(str(enc))} {shlex.quote(str(priv))}"
                            run(cmd, capture=True)
                        else:
                            actions.append({'action': 'encrypt_hidden_service_key_failed', 'err': 'gpg-not-found'})
                        actions.append({'action': 'encrypt_hidden_service_key', 'out': str(enc)})
                    except Exception as e:
                        actions.append({'action': 'encrypt_hidden_service_key_failed', 'err': str(e)})
    # Write nginx snippet (safe, idempotent)
    snippet_path = Path('/etc/nginx/snippets/onionsite_hardening.conf')
    try:
        snippet_path.parent.mkdir(parents=True, exist_ok=True)
        safe_backup(snippet_path)
        snippet_path.write_text(generate_nginx_snippet())
        actions.append({'action': 'write_nginx_snippet', 'file': str(snippet_path)})
    except Exception as e:
        actions.append({'action': 'write_nginx_snippet_failed', 'err': str(e)})
    # Create systemd overrides for nginx and tor
    for svc in ('nginx', 'tor'):
        override_dir = Path(f'/etc/systemd/system/{svc}.service.d')
        try:
            override_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        override_file = override_dir / 'onionsite-hardening.conf'
        if not override_file.exists():
            content = '''[Service]
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
LimitNOFILE=1024
'''
            try:
                safe_backup(override_file)
                override_file.write_text(content)
                actions.append({'action': 'write_systemd_override', 'service': svc, 'file': str(override_file)})
            except Exception as e:
                actions.append({'action': 'write_systemd_override_failed', 'service': svc, 'err': str(e)})
    # Ensure unattended-upgrades (best-effort)
    try:
        run('apt-get update >/dev/null 2>&1 || true', capture=True)
        run('DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades >/dev/null 2>&1 || true', capture=True)
        actions.append({'action': 'ensure_unattended_upgrades', 'status': 'attempted'})
    except Exception as e:
        actions.append({'action': 'unattended_upgrades_failed', 'err': str(e)})
    # Optional: setup ufw conservatively
    if setup_firewall:
        try:
            if shutil.which('ufw'):
                run('ufw default deny incoming', capture=True)
                run('ufw default allow outgoing', capture=True)
                run('ufw allow in on lo', capture=True)
                run('ufw --force enable', capture=True)
                actions.append({'action': 'configure_ufw', 'status': 'applied'})
            else:
                actions.append({'action': 'configure_ufw', 'status': 'ufw-not-installed'})
        except Exception as e:
            actions.append({'action': 'configure_firewall_failed', 'err': str(e)})
    # Optional: attempt ModSecurity install as advisory (will install Apache module; nginx connector is more complex)
    if enable_waf_flag_global():
        try:
            if shutil.which('apt'):
                run('DEBIAN_FRONTEND=noninteractive apt-get install -y libapache2-mod-security2 >/dev/null 2>&1 || true', capture=True)
                actions.append({'action': 'install_modsecurity', 'status': 'attempted'})
            else:
                actions.append({'action': 'install_modsecurity', 'status': 'apt-not-found'})
        except Exception as e:
            actions.append({'action': 'install_modsecurity_failed', 'err': str(e)})
    # Reload systemd and restart services (best-effort)
    try:
        run('systemctl daemon-reload', capture=True)
        run('systemctl restart tor || true', capture=True)
        run('systemctl restart nginx || true', capture=True)
        actions.append({'action': 'restart_services', 'services': ['tor', 'nginx']})
    except Exception as e:
        actions.append({'action': 'restart_services_failed', 'err': str(e)})

    # Lightweight nikto scan if available and HiddenServicePort known
    scan_results = {}
    nikto_bin = shutil.which('nikto')
    hs_target = detect_hidden_service_port()
    if nikto_bin and hs_target:
        # hs_target might already be '127.0.0.1:8080'
        try:
            cmd = f"{shlex.quote(nikto_bin)} -h http://{shlex.quote(hs_target)} -Display V"
            out = run(cmd, capture=True, timeout=300)
            scan_results['nikto'] = out.stdout
            actions.append({'action': 'nikto_scan', 'status': 'ran'})
        except Exception as e:
            actions.append({'action': 'nikto_scan_failed', 'err': str(e)})
    else:
        if not nikto_bin:
            actions.append({'action': 'nikto_scan', 'status': 'nikto-not-found'})
        elif not hs_target:
            actions.append({'action': 'nikto_scan', 'status': 'no-hiddenservice-port-found'})

    return actions, scan_results


# Because argparse doesn't allow passing enable_waf to apply_hardening directly in previous flow,
# provide a small global flag helper. It defaults to False and is set by arg parsing later.
_ENABLE_WAF_FLAG = False


def enable_waf_flag_global():
    return _ENABLE_WAF_FLAG


def write_report(findings, actions=None, scans=None):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        'timestamp': timestamp(),
        'findings': findings,
        'actions': actions or [],
        'scans': scans or {},
    }
    try:
        REPORT_FILE.write_text(json.dumps(payload, indent=2))
    except Exception as e:
        safe_log(f"report_write_failed {e}")
        return None
    safe_log("report written")
    return REPORT_FILE


def pretty_print(findings):
    for f in findings:
        status = 'OK' if f.get('ok') else 'ISSUE'
        print(f"[{status}] {f.get('name')}: {f.get('detail')}")


def install_systemd_service(webhook=None, admin_email=None, extra_services=None):
    if not is_root():
        raise SystemExit('install-service requires root')
    exec_path = shutil.which(os.path.basename(__file__)) or os.path.abspath(__file__)
    # Build command line carefully
    cmd_parts = [shlex.quote(exec_path), '--monitor']
    if webhook:
        cmd_parts += ['--webhook', shlex.quote(webhook)]
    if admin_email:
        cmd_parts += ['--admin-email', shlex.quote(admin_email)]
    if extra_services:
        for s in extra_services:
            cmd_parts += ['--service', shlex.quote(s)]
    cmd_str = ' '.join(cmd_parts)

    unit = f"""[Unit]
Description=Onionsite Hardener Monitor
After=network.target tor.service nginx.service

[Service]
Type=simple
ExecStart={cmd_str}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    try:
        SERVICE_UNIT_PATH.write_text(unit)
        run('systemctl daemon-reload', capture=True)
        run('systemctl enable --now onionsite-hardener-monitor.service', capture=True)
        return {'status': 'installed', 'unit': str(SERVICE_UNIT_PATH)}
    except Exception as e:
        return {'status': 'failed', 'err': str(e)}


def monitor_mode(webhook=None, admin_email=None, extra_services=None):
    services = ['tor', 'nginx'] + (extra_services or [])
    print('Starting monitor for services:', ','.join(services))
    # Build journalctl command
    jcmd = ['journalctl', '-f', '-o', 'short']
    for s in services:
        jcmd += ['-u', s]
    try:
        p = subprocess.Popen(jcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        safe_log(f"journalctl_spawn_failed {e}")
        print("Failed to start journalctl:", e)
        return

    # Tail logs if present
    tail_files = []
    if Path('/var/log/nginx/access.log').exists():
        tail_files.append('/var/log/nginx/access.log')
    if Path('/var/log/nginx/error.log').exists():
        tail_files.append('/var/log/nginx/error.log')
    tails = []
    for f in tail_files:
        try:
            t = subprocess.Popen(['tail', '-n', '200', '-F', f], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tails.append((f, t))
        except Exception:
            continue

    error_count = 0
    last_alert = 0
    try:
        while True:
            # Read a line from journalctl stdout
            line = p.stdout.readline()
            if line:
                print(line, end='')
                if 'error' in line.lower() or 'failed' in line.lower():
                    error_count += 1
            # Read tails
            for fname, proc in tails:
                if proc.stdout:
                    o = proc.stdout.readline()
                    if o:
                        print(f'[{fname}]', o, end='')
                        if ' 500 ' in o or ' 502 ' in o or ' 503 ' in o:
                            error_count += 1
            now = time.time()
            if error_count > 100 and (now - last_alert) > 300:
                alert = f'High error rate detected: {error_count} errors in monitor window'
                print('ALERT:', alert)
                safe_log(f"alert {alert}")
                if webhook:
                    try:
                        # best-effort POST JSON
                        run(f"curl -s -X POST -H 'Content-Type: application/json' -d '{json.dumps({'text': alert})}' {shlex.quote(webhook)}", capture=True)
                    except Exception:
                        pass
                if admin_email:
                    try:
                        run(f"echo {shlex.quote(alert)} | mail -s 'Onionsite Alert' {shlex.quote(admin_email)}", capture=True)
                    except Exception:
                        pass
                last_alert = now
                error_count = 0
            time.sleep(0.1)
    except KeyboardInterrupt:
        print('\nMonitoring stopped by user')
    finally:
        try:
            p.terminate()
        except Exception:
            pass
        for _, proc in tails:
            try:
                proc.terminate()
            except Exception:
                pass


def main():
    global _ENABLE_WAF_FLAG
    parser = argparse.ArgumentParser(description='Onionsite Hardening & Monitor Tool ')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--monitor', action='store_true')
    parser.add_argument('--report', action='store_true')
    parser.add_argument('--install-service', action='store_true')
    parser.add_argument('--enable-waf', action='store_true', help='Attempt to install ModSecurity (advisory)')
    parser.add_argument('--backup-key', action='store_true', help='Back up hidden service private_key')
    parser.add_argument('--encrypt-key', action='store_true', help='Encrypt hidden service private_key backup with gpg')
    parser.add_argument('--gpg-recipient', type=str, default=None, help='GPG recipient (email or key id) for encrypting key')
    parser.add_argument('--scan-nikto', action='store_true')
    parser.add_argument('--setup-firewall', action='store_true', help='Conservative ufw setup (deny incoming, allow outgoing)')
    parser.add_argument('--service', action='append', default=[], help='additional systemd service to monitor')
    parser.add_argument('--no-interact', action='store_true')
    parser.add_argument('--webhook', type=str, default=None, help='optional webhook URL for alerts')
    parser.add_argument('--admin-email', type=str, default=None, help='admin email for alerts (requires mail util)')
    args = parser.parse_args()

    _ENABLE_WAF_FLAG = args.enable_waf

    findings = []
    findings += check_tor()
    findings += check_nginx()
    findings += check_system()

    if args.check:
        pretty_print(findings)

    actions = []
    scans = {}

    if args.apply:
        if not is_root():
            print('Apply requires root. Re-run with sudo.')
            sys.exit(2)
        if not args.no_interact:
            print('This will make system changes and create backups at', BACKUP_DIR)
            resp = input('Proceed? [y/N] ').strip().lower()
            if resp != 'y':
                print('Aborted')
                sys.exit(1)
        actions, scans = apply_hardening(enable_waf=args.enable_waf, setup_firewall=args.setup_firewall,
                                         backup_key=args.backup_key, encrypt_key=args.encrypt_key, gpg_recipient=args.gpg_recipient)
        print('Actions performed:')
        for a in actions:
            print('-', a)

    if args.scan_nikto:
        nikto_bin = shutil.which('nikto')
        hs_target = detect_hidden_service_port()
        if nikto_bin and hs_target:
            print('Running nikto scan against', hs_target)
            try:
                cmd = f"{shlex.quote(nikto_bin)} -h http://{shlex.quote(hs_target)} -Display V"
                out = run(cmd, capture=True, timeout=300)
                scans['nikto'] = out.stdout
                print(out.stdout)
            except Exception as e:
                print('Nikto scan failed:', e)
        else:
            print('Nikto not found or HiddenServicePort not detected')

    if args.report:
        rpt = write_report(findings, actions, scans)
        if rpt:
            print('Report written to', rpt)
        else:
            print('Failed to write report; check logs')

    if args.install_service:
        res = install_systemd_service(webhook=args.webhook, admin_email=args.admin_email, extra_services=args.service)
        print('Install service result:', res)

    if args.monitor:
        try:
            monitor_mode(webhook=args.webhook, admin_email=args.admin_email, extra_services=args.service)
        except Exception as e:
            safe_log(f"monitor_failed {e}")
            print('Monitor failed:', e)

    if not (args.check or args.apply or args.report or args.monitor or args.install_service):
        parser.print_help()


if __name__ == '__main__':
    main()

