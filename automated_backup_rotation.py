#!/usr/bin/env python3
"""
Automated Backup and Key Rotation System
Enterprise-grade automated backup with encryption and rotation policies
"""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import hashlib

# Configuration
BACKUP_ROOT = Path('/var/backups/onionsite')
ENCRYPTED_BACKUP_DIR = BACKUP_ROOT / 'encrypted'
KEY_BACKUP_DIR = BACKUP_ROOT / 'keys'
CONFIG_BACKUP_DIR = BACKUP_ROOT / 'configs'
ROTATION_POLICY = {
    'daily': 7,      # Keep 7 daily backups
    'weekly': 4,     # Keep 4 weekly backups
    'monthly': 12,   # Keep 12 monthly backups
    'yearly': 5      # Keep 5 yearly backups
}
BACKUP_LOG = Path('/var/log/onionsite-backup/backup.log')
BACKUP_METADATA = BACKUP_ROOT / 'metadata.json'


def is_root():
    return os.geteuid() == 0


def timestamp():
    return datetime.utcnow().isoformat() + 'Z'


def log(message: str, level: str = 'INFO'):
    """Log backup operations"""
    entry = f"[{timestamp()}] [{level}] {message}\n"
    try:
        BACKUP_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(BACKUP_LOG, 'a') as f:
            f.write(entry)
    except Exception:
        pass
    print(entry.strip())


def run_cmd(cmd: str, capture: bool = True) -> subprocess.CompletedProcess:
    """Execute shell command safely"""
    try:
        return subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None, text=True, timeout=300
        )
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, '', str(e))


def calculate_checksum(file_path: Path) -> str:
    """Calculate SHA256 checksum of file"""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return ''


def encrypt_file(input_path: Path, output_path: Path, gpg_recipient: Optional[str] = None) -> bool:
    """Encrypt file using GPG"""
    if not shutil.which('gpg'):
        log('GPG not found, skipping encryption', 'WARN')
        return False
    
    try:
        if gpg_recipient:
            cmd = f"gpg --yes --batch -o {shlex.quote(str(output_path))} --encrypt -r {shlex.quote(gpg_recipient)} {shlex.quote(str(input_path))}"
        else:
            cmd = f"gpg --yes --batch --symmetric --cipher-algo AES256 -o {shlex.quote(str(output_path))} {shlex.quote(str(input_path))}"
        
        result = run_cmd(cmd)
        if result.returncode == 0:
            log(f'Encrypted {input_path} -> {output_path}')
            return True
        else:
            log(f'Encryption failed: {result.stderr}', 'ERROR')
            return False
    except Exception as e:
        log(f'Encryption error: {e}', 'ERROR')
        return False


def backup_hidden_service_keys(encrypt: bool = True, gpg_recipient: Optional[str] = None) -> Optional[Path]:
    """Backup Tor hidden service keys"""
    if not is_root():
        log('Root privileges required', 'ERROR')
        return None
    
    hs_dir = Path('/var/lib/tor/onion_service')
    if not hs_dir.exists():
        log('Hidden service directory not found', 'WARN')
        return None
    
    KEY_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    backup_name = f'hs_keys_{ts}.tar.gz'
    backup_path = KEY_BACKUP_DIR / backup_name
    
    try:
        with tarfile.open(backup_path, 'w:gz') as tar:
            tar.add(hs_dir, arcname='onion_service', recursive=True)
        
        checksum = calculate_checksum(backup_path)
        log(f'Backed up hidden service keys: {backup_path} (SHA256: {checksum[:16]}...)')
        
        # Encrypt if requested
        if encrypt:
            encrypted_path = ENCRYPTED_BACKUP_DIR / f'{backup_name}.gpg'
            ENCRYPTED_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            if encrypt_file(backup_path, encrypted_path, gpg_recipient):
                # Optionally remove unencrypted backup
                # backup_path.unlink()
                backup_path = encrypted_path
        
        # Update metadata
        update_backup_metadata('keys', backup_path, checksum)
        
        return backup_path
    except Exception as e:
        log(f'Backup failed: {e}', 'ERROR')
        return None


def backup_configurations() -> Optional[Path]:
    """Backup all configuration files"""
    if not is_root():
        log('Root privileges required', 'ERROR')
        return None
    
    CONFIG_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    backup_name = f'configs_{ts}.tar.gz'
    backup_path = CONFIG_BACKUP_DIR / backup_name
    
    config_files = [
        '/etc/tor/torrc',
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-available/onion_site',
        '/etc/nginx/sites-enabled/onion_site',
        '/etc/fail2ban/jail.d/onionsite.conf',
        '/etc/nftables/onionsite-security.nft',
    ]
    
    try:
        with tarfile.open(backup_path, 'w:gz') as tar:
            for config_file in config_files:
                path = Path(config_file)
                if path.exists():
                    tar.add(path, arcname=path.name)
        
        checksum = calculate_checksum(backup_path)
        log(f'Backed up configurations: {backup_path} (SHA256: {checksum[:16]}...)')
        
        update_backup_metadata('configs', backup_path, checksum)
        
        return backup_path
    except Exception as e:
        log(f'Config backup failed: {e}', 'ERROR')
        return None


def backup_webroot() -> Optional[Path]:
    """Backup web root directory"""
    if not is_root():
        log('Root privileges required', 'ERROR')
        return None
    
    webroot = Path('/var/www/onion_site')
    if not webroot.exists():
        log('Web root not found', 'WARN')
        return None
    
    CONFIG_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    backup_name = f'webroot_{ts}.tar.gz'
    backup_path = CONFIG_BACKUP_DIR / backup_name
    
    try:
        with tarfile.open(backup_path, 'w:gz') as tar:
            tar.add(webroot, arcname='onion_site', recursive=True)
        
        checksum = calculate_checksum(backup_path)
        log(f'Backed up webroot: {backup_path} (SHA256: {checksum[:16]}...)')
        
        update_backup_metadata('webroot', backup_path, checksum)
        
        return backup_path
    except Exception as e:
        log(f'Webroot backup failed: {e}', 'ERROR')
        return None


def update_backup_metadata(backup_type: str, backup_path: Path, checksum: str):
    """Update backup metadata database"""
    try:
        if BACKUP_METADATA.exists():
            with open(BACKUP_METADATA, 'r') as f:
                metadata = json.load(f)
        else:
            metadata = {}
        
        if backup_type not in metadata:
            metadata[backup_type] = []
        
        entry = {
            'path': str(backup_path),
            'timestamp': timestamp(),
            'checksum': checksum,
            'size': backup_path.stat().st_size if backup_path.exists() else 0
        }
        
        metadata[backup_type].append(entry)
        
        with open(BACKUP_METADATA, 'w') as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        log(f'Metadata update failed: {e}', 'WARN')


def rotate_backups():
    """Apply rotation policy to old backups"""
    if not is_root():
        return
    
    log('Starting backup rotation...')
    
    now = datetime.utcnow()
    deleted_count = 0
    
    for backup_type in ['keys', 'configs', 'webroot']:
        backup_dir = BACKUP_ROOT / backup_type if backup_type == 'keys' else CONFIG_BACKUP_DIR
        
        if not backup_dir.exists():
            continue
        
        backups = sorted(backup_dir.glob('*'), key=lambda p: p.stat().st_mtime, reverse=True)
        
        # Keep daily backups for 7 days
        daily_cutoff = now - timedelta(days=ROTATION_POLICY['daily'])
        daily_backups = [b for b in backups if datetime.fromtimestamp(b.stat().st_mtime) > daily_cutoff]
        
        # Keep weekly backups
        weekly_cutoff = now - timedelta(weeks=ROTATION_POLICY['weekly'])
        weekly_backups = [b for b in backups if datetime.fromtimestamp(b.stat().st_mtime) > weekly_cutoff]
        
        # Keep monthly backups
        monthly_cutoff = now - timedelta(days=ROTATION_POLICY['monthly'] * 30)
        monthly_backups = [b for b in backups if datetime.fromtimestamp(b.stat().st_mtime) > monthly_cutoff]
        
        # Determine which backups to keep
        keep = set(daily_backups[:ROTATION_POLICY['daily']])
        
        # Add weekly backups (first backup of each week)
        for backup in backups:
            if len(keep) >= ROTATION_POLICY['daily'] + ROTATION_POLICY['weekly']:
                break
            backup_date = datetime.fromtimestamp(backup.stat().st_mtime)
            if backup_date > weekly_cutoff and backup not in keep:
                # Check if it's the first backup of the week
                week_start = backup_date - timedelta(days=backup_date.weekday())
                if backup_date.date() == week_start.date():
                    keep.add(backup)
        
        # Delete backups not in keep set
        for backup in backups:
            if backup not in keep:
                try:
                    backup.unlink()
                    deleted_count += 1
                    log(f'Deleted old backup: {backup.name}')
                except Exception as e:
                    log(f'Failed to delete {backup.name}: {e}', 'WARN')
    
    log(f'Rotation complete. Deleted {deleted_count} old backups')


def rotate_keys(backup_first: bool = True, encrypt: bool = True, gpg_recipient: Optional[str] = None) -> bool:
    """Rotate Tor hidden service keys (generate new onion address)"""
    if not is_root():
        log('Root privileges required', 'ERROR')
        return False
    
    log('Starting key rotation...')
    
    # Backup existing keys first
    if backup_first:
        backup_hidden_service_keys(encrypt=encrypt, gpg_recipient=gpg_recipient)
    
    hs_dir = Path('/var/lib/tor/onion_service')
    
    # Stop Tor
    run_cmd('systemctl stop tor@default || systemctl stop tor', capture=True)
    time.sleep(2)
    
    # Securely remove old keys
    if hs_dir.exists():
        for key_file in hs_dir.glob('*'):
            if key_file.is_file():
                # Secure deletion using shred
                run_cmd(f'shred -u -z -n 3 {shlex.quote(str(key_file))}', capture=True)
    
    # Start Tor to generate new keys
    run_cmd('systemctl start tor@default || systemctl start tor', capture=True)
    
    # Wait for new hostname
    log('Waiting for new hostname generation...')
    for i in range(30):
        hostname_file = hs_dir / 'hostname'
        if hostname_file.exists():
            new_hostname = hostname_file.read_text().strip()
            log(f'New onion address generated: {new_hostname}')
            return True
        time.sleep(1)
    
    log('Key rotation failed: hostname not generated', 'ERROR')
    return False


def full_backup(encrypt: bool = True, gpg_recipient: Optional[str] = None) -> Dict:
    """Perform full system backup"""
    if not is_root():
        log('Root privileges required', 'ERROR')
        return {}
    
    log('Starting full backup...')
    
    results = {
        'keys': None,
        'configs': None,
        'webroot': None,
        'timestamp': timestamp()
    }
    
    results['keys'] = str(backup_hidden_service_keys(encrypt=encrypt, gpg_recipient=gpg_recipient)) if backup_hidden_service_keys(encrypt=encrypt, gpg_recipient=gpg_recipient) else None
    results['configs'] = str(backup_configurations()) if backup_configurations() else None
    results['webroot'] = str(backup_webroot()) if backup_webroot() else None
    
    # Rotate old backups
    rotate_backups()
    
    log('Full backup complete')
    return results


def restore_backup(backup_path: Path, backup_type: str = 'keys') -> bool:
    """Restore from backup"""
    if not is_root():
        log('Root privileges required', 'ERROR')
        return False
    
    log(f'Restoring {backup_type} from {backup_path}...')
    
    # Decrypt if needed
    if backup_path.suffix == '.gpg':
        decrypted_path = backup_path.with_suffix('')
        if not shutil.which('gpg'):
            log('GPG not found, cannot decrypt', 'ERROR')
            return False
        
        cmd = f"gpg --yes --batch -o {shlex.quote(str(decrypted_path))} --decrypt {shlex.quote(str(backup_path))}"
        result = run_cmd(cmd)
        if result.returncode != 0:
            log(f'Decryption failed: {result.stderr}', 'ERROR')
            return False
        backup_path = decrypted_path
    
    try:
        if backup_type == 'keys':
            hs_dir = Path('/var/lib/tor/onion_service')
            run_cmd('systemctl stop tor@default || systemctl stop tor', capture=True)
            
            with tarfile.open(backup_path, 'r:gz') as tar:
                tar.extractall(hs_dir.parent)
            
            run_cmd('chown -R debian-tor:debian-tor /var/lib/tor/onion_service', capture=True)
            run_cmd('chmod 700 /var/lib/tor/onion_service', capture=True)
            run_cmd('systemctl start tor@default || systemctl start tor', capture=True)
            
        elif backup_type in ['configs', 'webroot']:
            with tarfile.open(backup_path, 'r:gz') as tar:
                tar.extractall('/')
        
        log(f'Restore complete: {backup_path}')
        return True
    except Exception as e:
        log(f'Restore failed: {e}', 'ERROR')
        return False


if __name__ == '__main__':
    import argparse
    import time
    
    parser = argparse.ArgumentParser(description='Automated Backup and Key Rotation')
    parser.add_argument('--backup', action='store_true', help='Perform full backup')
    parser.add_argument('--backup-keys', action='store_true', help='Backup hidden service keys')
    parser.add_argument('--backup-configs', action='store_true', help='Backup configurations')
    parser.add_argument('--backup-webroot', action='store_true', help='Backup webroot')
    parser.add_argument('--rotate-keys', action='store_true', help='Rotate Tor keys')
    parser.add_argument('--rotate-backups', action='store_true', help='Apply rotation policy')
    parser.add_argument('--restore', type=str, help='Restore from backup file')
    parser.add_argument('--restore-type', type=str, default='keys', choices=['keys', 'configs', 'webroot'])
    parser.add_argument('--encrypt', action='store_true', help='Encrypt backups')
    parser.add_argument('--gpg-recipient', type=str, help='GPG recipient for encryption')
    parser.add_argument('--auto', action='store_true', help='Enable automated backups (systemd service)')
    
    args = parser.parse_args()
    
    if args.backup:
        results = full_backup(encrypt=args.encrypt, gpg_recipient=args.gpg_recipient)
        print(json.dumps(results, indent=2))
    elif args.backup_keys:
        backup_hidden_service_keys(encrypt=args.encrypt, gpg_recipient=args.gpg_recipient)
    elif args.backup_configs:
        backup_configurations()
    elif args.backup_webroot:
        backup_webroot()
    elif args.rotate_keys:
        rotate_keys(backup_first=True, encrypt=args.encrypt, gpg_recipient=args.gpg_recipient)
    elif args.rotate_backups:
        rotate_backups()
    elif args.restore:
        restore_backup(Path(args.restore), args.restore_type)
    elif args.auto:
        # Create systemd service for automated backups
        service_content = f"""[Unit]
Description=OnionSite Automated Backup Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {Path(__file__).absolute()} --backup --encrypt
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
        
        run_cmd('systemctl daemon-reload', capture=True)
        run_cmd('systemctl enable --now onionsite-backup.timer', capture=True)
        log('Automated backup service installed and enabled')
    else:
        parser.print_help()

