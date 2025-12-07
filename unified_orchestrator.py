#!/usr/bin/env python3
"""
Unified Enterprise-Grade OnionSite Orchestrator
Integrates all security modules into a single, fully automated system
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Import all modules
try:
    from advanced_security_module import apply_all_security, check_security_status
    from automated_backup_rotation import full_backup, rotate_keys, rotate_backups
    from comprehensive_monitoring import monitoring_loop, collect_system_metrics, update_dashboard
    from security_scanner import comprehensive_scan, generate_report
except ImportError as e:
    print(f"Warning: Could not import modules: {e}")
    print("Some features may not be available.")


CONFIG_FILE = Path('/etc/onionsite-orchestrator/config.json')
LOG_FILE = Path('/var/log/onionsite-orchestrator/unified.log')


def is_root():
    return os.geteuid() == 0


def timestamp():
    return datetime.utcnow().isoformat() + 'Z'


def log(message: str, level: str = 'INFO'):
    """Unified logging"""
    entry = f"[{timestamp()}] [{level}] {message}\n"
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(entry)
    except:
        pass
    print(entry.strip())


def load_config() -> dict:
    """Load configuration"""
    default_config = {
        'security': {
            'fail2ban': True,
            'ids': True,
            'apparmor': True,
            'firewall': True,
            'rate_limiting': True
        },
        'backup': {
            'enabled': True,
            'encrypt': True,
            'gpg_recipient': None,
            'auto_rotate_keys': False,
            'rotation_days': 90
        },
        'monitoring': {
            'enabled': True,
            'interval': 60,
            'webhook': None,
            'email': None
        },
        'scanning': {
            'auto_scan': True,
            'scan_interval_hours': 24
        }
    }
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                user_config = json.load(f)
            # Merge with defaults
            default_config.update(user_config)
        except:
            pass
    
    return default_config


def save_config(config: dict):
    """Save configuration"""
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        log(f'Failed to save config: {e}', 'ERROR')


def deploy_full_stack(config: dict = None):
    """Deploy complete OnionSite stack with all security features"""
    if not is_root():
        log('Root privileges required', 'ERROR')
        return False
    
    if config is None:
        config = load_config()
    
    log('=' * 80)
    log('DEPLOYING ENTERPRISE-GRADE ONIONSITE STACK')
    log('=' * 80)
    
    results = {
        'deployment': {},
        'security': {},
        'backup': {},
        'monitoring': {},
        'scanning': {}
    }
    
    # Step 1: Deploy base OnionSite (using bash script)
    log('Step 1: Deploying base OnionSite...')
    try:
        orchestrator_script = Path('/usr/local/bin/onionsite-orchestrator.sh')
        if orchestrator_script.exists():
            result = subprocess.run(
                ['bash', str(orchestrator_script), '--install', '--auto'],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                results['deployment']['base'] = 'success'
                log('Base deployment successful')
            else:
                results['deployment']['base'] = 'failed'
                log(f'Base deployment failed: {result.stderr}', 'ERROR')
        else:
            log('OnionSite orchestrator script not found. Please install it first.', 'ERROR')
            return False
    except Exception as e:
        log(f'Deployment error: {e}', 'ERROR')
        results['deployment']['base'] = 'failed'
        return False
    
    time.sleep(5)  # Wait for services to stabilize
    
    # Step 2: Apply all security measures
    if any(config.get('security', {}).values()):
        log('Step 2: Applying security hardening...')
        try:
            security_results = apply_all_security()
            results['security'] = security_results
            log('Security hardening complete')
        except Exception as e:
            log(f'Security hardening error: {e}', 'ERROR')
            results['security'] = {'error': str(e)}
    
    # Step 3: Setup automated backups
    if config.get('backup', {}).get('enabled', True):
        log('Step 3: Setting up automated backups...')
        try:
            backup_result = full_backup(
                encrypt=config.get('backup', {}).get('encrypt', True),
                gpg_recipient=config.get('backup', {}).get('gpg_recipient')
            )
            results['backup']['initial'] = backup_result
            log('Initial backup complete')
        except Exception as e:
            log(f'Backup setup error: {e}', 'ERROR')
            results['backup']['error'] = str(e)
    
    # Step 4: Setup monitoring
    if config.get('monitoring', {}).get('enabled', True):
        log('Step 4: Setting up monitoring...')
        try:
            # Install monitoring service
            install_monitoring_service(config.get('monitoring', {}))
            results['monitoring']['status'] = 'installed'
            log('Monitoring service installed')
        except Exception as e:
            log(f'Monitoring setup error: {e}', 'ERROR')
            results['monitoring']['error'] = str(e)
    
    # Step 5: Run initial security scan
    if config.get('scanning', {}).get('auto_scan', True):
        log('Step 5: Running initial security scan...')
        try:
            scan_results = comprehensive_scan()
            results['scanning']['initial'] = {
                'risk_score': scan_results.get('risk_score', 0),
                'timestamp': scan_results.get('scan_timestamp')
            }
            log(f'Initial scan complete. Risk score: {scan_results.get("risk_score", 0)}/100')
        except Exception as e:
            log(f'Scan error: {e}', 'ERROR')
            results['scanning']['error'] = str(e)
    
    log('=' * 80)
    log('DEPLOYMENT COMPLETE')
    log('=' * 80)
    
    # Save deployment results
    results_file = Path('/var/log/onionsite-orchestrator/deployment_results.json')
    results_file.parent.mkdir(parents=True, exist_ok=True)
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    return results


def install_monitoring_service(monitoring_config: dict):
    """Install monitoring as systemd service"""
    script_path = Path(__file__).parent / 'comprehensive_monitoring.py'
    
    service_content = f"""[Unit]
Description=OnionSite Comprehensive Monitoring
After=network.target tor.service nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script_path.absolute()} --monitor --interval {monitoring_config.get('interval', 60)} --webhook {monitoring_config.get('webhook', '') or ''} --email {monitoring_config.get('email', '') or ''}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    service_file = Path('/etc/systemd/system/onionsite-monitoring.service')
    service_file.write_text(service_content)
    
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'onionsite-monitoring.service'], check=True)


def install_backup_service(backup_config: dict):
    """Install automated backup service"""
    script_path = Path(__file__).parent / 'automated_backup_rotation.py'
    
    service_content = f"""[Unit]
Description=OnionSite Automated Backup
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {script_path.absolute()} --backup --encrypt{' --gpg-recipient ' + backup_config.get('gpg_recipient') if backup_config.get('gpg_recipient') else ''}
"""
    
    service_file = Path('/etc/systemd/system/onionsite-backup.service')
    service_file.write_text(service_content)
    
    timer_content = """[Unit]
Description=OnionSite Automated Backup Timer

[Timer]
OnBootSec=1h
OnUnitActiveSec=24h

[Install]
WantedBy=timers.target
"""
    
    timer_file = Path('/etc/systemd/system/onionsite-backup.timer')
    timer_file.write_text(timer_content)
    
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'onionsite-backup.timer'], check=True)


def install_scan_service(scan_config: dict):
    """Install automated security scanning service"""
    script_path = Path(__file__).parent / 'security_scanner.py'
    interval_hours = scan_config.get('scan_interval_hours', 24)
    
    service_content = f"""[Unit]
Description=OnionSite Security Scanner
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {script_path.absolute()} --scan --report
"""
    
    service_file = Path('/etc/systemd/system/onionsite-scanner.service')
    service_file.write_text(service_content)
    
    timer_content = f"""[Unit]
Description=OnionSite Security Scanner Timer

[Timer]
OnBootSec=1h
OnUnitActiveSec={interval_hours}h

[Install]
WantedBy=timers.target
"""
    
    timer_file = Path('/etc/systemd/system/onionsite-scanner.timer')
    timer_file.write_text(timer_content)
    
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'onionsite-scanner.timer'], check=True)


def status_report():
    """Generate comprehensive status report"""
    if not is_root():
        log('Root privileges required', 'ERROR')
        return
    
    log('=' * 80)
    log('ONIONSITE STATUS REPORT')
    log('=' * 80)
    
    # Base services
    log('\nBASE SERVICES:')
    for service in ['tor', 'nginx', 'fail2ban']:
        result = subprocess.run(
            ['systemctl', 'is-active', service],
            capture_output=True, text=True
        )
        status = 'ACTIVE' if result.returncode == 0 else 'INACTIVE'
        log(f'  {service}: {status}')
    
    # Security status
    log('\nSECURITY STATUS:')
    try:
        security_status = check_security_status()
        for component, status in security_status.items():
            if isinstance(status, bool):
                status_str = 'ENABLED' if status else 'DISABLED'
                log(f'  {component}: {status_str}')
    except:
        log('  Security status check failed', 'ERROR')
    
    # Monitoring
    log('\nMONITORING:')
    result = subprocess.run(
        ['systemctl', 'is-active', 'onionsite-monitoring.service'],
        capture_output=True, text=True
    )
    monitoring_status = 'ACTIVE' if result.returncode == 0 else 'INACTIVE'
    log(f'  Monitoring Service: {monitoring_status}')
    
    # Backups
    log('\nBACKUPS:')
    backup_dir = Path('/var/backups/onionsite')
    if backup_dir.exists():
        backup_count = len(list(backup_dir.rglob('*')))
        log(f'  Backup files: {backup_count}')
    else:
        log('  No backups found')
    
    # Recent scans
    log('\nSECURITY SCANS:')
    scan_dir = Path('/var/lib/onionsite-security/scans')
    if scan_dir.exists():
        scans = sorted(scan_dir.glob('scan_*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        if scans:
            latest_scan = scans[0]
            try:
                with open(latest_scan, 'r') as f:
                    scan_data = json.load(f)
                risk_score = scan_data.get('risk_score', 0)
                log(f'  Latest scan risk score: {risk_score}/100')
                log(f'  Latest scan: {latest_scan.name}')
            except:
                log('  Could not read latest scan')
        else:
            log('  No scans found')
    else:
        log('  Scan directory not found')
    
    log('=' * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Unified Enterprise-Grade OnionSite Orchestrator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Deploy complete stack
  sudo python3 unified_orchestrator.py --deploy

  # Status report
  sudo python3 unified_orchestrator.py --status

  # Apply security only
  sudo python3 unified_orchestrator.py --security

  # Run backup
  sudo python3 unified_orchestrator.py --backup

  # Run security scan
  sudo python3 unified_orchestrator.py --scan
        """
    )
    
    parser.add_argument('--deploy', action='store_true',
                       help='Deploy complete OnionSite stack with all security features')
    parser.add_argument('--status', action='store_true',
                       help='Show comprehensive status report')
    parser.add_argument('--security', action='store_true',
                       help='Apply all security measures')
    parser.add_argument('--backup', action='store_true',
                       help='Perform full backup')
    parser.add_argument('--scan', action='store_true',
                       help='Run security scan')
    parser.add_argument('--monitor', action='store_true',
                       help='Start monitoring (foreground)')
    parser.add_argument('--rotate-keys', action='store_true',
                       help='Rotate Tor hidden service keys')
    parser.add_argument('--config', type=str,
                       help='Path to configuration file')
    parser.add_argument('--install-services', action='store_true',
                       help='Install all automated services (backup, monitoring, scanning)')
    
    args = parser.parse_args()
    
    if not args.deploy and not args.status and not args.security and not args.backup and not args.scan and not args.monitor and not args.rotate_keys and not args.install_services:
        parser.print_help()
        return
    
    if not is_root():
        log('This script requires root privileges', 'ERROR')
        sys.exit(1)
    
    config = load_config()
    if args.config:
        try:
            with open(args.config, 'r') as f:
                user_config = json.load(f)
            config.update(user_config)
        except Exception as e:
            log(f'Failed to load config: {e}', 'ERROR')
    
    if args.deploy:
        deploy_full_stack(config)
    elif args.status:
        status_report()
    elif args.security:
        log('Applying security measures...')
        results = apply_all_security()
        print(json.dumps(results, indent=2))
    elif args.backup:
        log('Performing backup...')
        results = full_backup(
            encrypt=config.get('backup', {}).get('encrypt', True),
            gpg_recipient=config.get('backup', {}).get('gpg_recipient')
        )
        print(json.dumps(results, indent=2))
    elif args.scan:
        log('Running security scan...')
        results = comprehensive_scan()
        print(generate_report(results))
    elif args.monitor:
        monitoring_config = config.get('monitoring', {})
        monitoring_loop(
            interval=monitoring_config.get('interval', 60),
            webhook=monitoring_config.get('webhook'),
            email=monitoring_config.get('email')
        )
    elif args.rotate_keys:
        log('Rotating keys...')
        backup_config = config.get('backup', {})
        rotate_keys(
            backup_first=True,
            encrypt=backup_config.get('encrypt', True),
            gpg_recipient=backup_config.get('gpg_recipient')
        )
    elif args.install_services:
        log('Installing automated services...')
        install_backup_service(config.get('backup', {}))
        install_scan_service(config.get('scanning', {}))
        log('Services installed and enabled')


if __name__ == '__main__':
    main()

