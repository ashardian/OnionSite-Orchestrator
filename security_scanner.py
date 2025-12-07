#!/usr/bin/env python3
"""
Security Scanner and Vulnerability Assessment Module
Comprehensive security scanning with multiple tools and automated reporting
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Configuration
SCAN_RESULTS_DIR = Path('/var/lib/onionsite-security/scans')
SCAN_REPORT_DIR = Path('/var/log/onionsite-security/scans')
VULN_DB = Path('/var/lib/onionsite-security/vulnerabilities.json')

# CVE database (simplified - in production, use official feeds)
KNOWN_VULNS = {
    'nginx': {},
    'tor': {},
    'openssl': {}
}


def is_root():
    return os.geteuid() == 0


def timestamp():
    return datetime.utcnow().isoformat() + 'Z'


def run_cmd(cmd: str, capture: bool = True, timeout: Optional[int] = 300) -> subprocess.CompletedProcess:
    """Execute shell command"""
    try:
        return subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, '', 'timeout')
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, '', str(e))


def scan_ports() -> Dict:
    """Scan open ports and services"""
    results = {
        'timestamp': timestamp(),
        'open_ports': [],
        'listening_services': [],
        'vulnerabilities': []
    }
    
    # Use ss to get listening ports
    result = run_cmd('ss -tlnp', capture=True)
    if result.returncode == 0:
        for line in result.stdout.split('\n')[1:]:  # Skip header
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    state = parts[0]
                    local_addr = parts[3]
                    if 'LISTEN' in state:
                        results['listening_services'].append({
                            'address': local_addr,
                            'state': state
                        })
                        
                        # Check if port should be closed
                        if not local_addr.startswith('127.0.0.1') and not local_addr.startswith('::1'):
                            results['vulnerabilities'].append({
                                'severity': 'medium',
                                'type': 'exposed_port',
                                'description': f'Port listening on non-localhost: {local_addr}',
                                'recommendation': 'Bind service to localhost only'
                            })
    
    return results


def scan_file_permissions() -> Dict:
    """Scan file permissions for security issues"""
    results = {
        'timestamp': timestamp(),
        'issues': []
    }
    
    critical_files = [
        ('/etc/tor/torrc', 0o644),
        ('/var/lib/tor/onion_service', 0o700),
        ('/etc/nginx/nginx.conf', 0o644),
        ('/etc/passwd', 0o644),
        ('/etc/shadow', 0o640),
    ]
    
    for file_path, expected_mode in critical_files:
        path = Path(file_path)
        if path.exists():
            actual_mode = oct(path.stat().st_mode & 0o777)
            expected_oct = oct(expected_mode)
            
            if actual_mode != expected_oct:
                results['issues'].append({
                    'severity': 'high' if 'shadow' in file_path or 'tor' in file_path else 'medium',
                    'file': file_path,
                    'expected': expected_oct,
                    'actual': actual_mode,
                    'description': f'Incorrect permissions on {file_path}'
                })
    
    return results


def scan_nginx_config() -> Dict:
    """Scan Nginx configuration for security issues"""
    results = {
        'timestamp': timestamp(),
        'issues': [],
        'recommendations': []
    }
    
    nginx_conf = Path('/etc/nginx/nginx.conf')
    site_conf = Path('/etc/nginx/sites-available/onion_site')
    
    configs_to_check = [nginx_conf, site_conf]
    
    for config_file in configs_to_check:
        if not config_file.exists():
            continue
        
        try:
            content = config_file.read_text()
            
            # Check for server_tokens
            if 'server_tokens off' not in content:
                results['issues'].append({
                    'severity': 'low',
                    'file': str(config_file),
                    'type': 'information_disclosure',
                    'description': 'server_tokens not disabled',
                    'recommendation': 'Add "server_tokens off;" to hide Nginx version'
                })
            
            # Check for security headers
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security'
            ]
            
            for header in security_headers:
                if header not in content:
                    results['recommendations'].append({
                        'type': 'security_header',
                        'header': header,
                        'description': f'Missing security header: {header}'
                    })
            
            # Check for exposed ports
            if 'listen 0.0.0.0' in content or 'listen *' in content:
                results['issues'].append({
                    'severity': 'high',
                    'file': str(config_file),
                    'type': 'exposed_service',
                    'description': 'Nginx listening on all interfaces',
                    'recommendation': 'Bind to 127.0.0.1 only'
                })
            
            # Check for directory listing
            if 'autoindex on' in content:
                results['issues'].append({
                    'severity': 'medium',
                    'file': str(config_file),
                    'type': 'directory_listing',
                    'description': 'Directory listing enabled',
                    'recommendation': 'Disable directory listing'
                })
            
        except Exception as e:
            results['issues'].append({
                'severity': 'low',
                'file': str(config_file),
                'type': 'scan_error',
                'description': f'Error reading config: {e}'
            })
    
    return results


def scan_tor_config() -> Dict:
    """Scan Tor configuration for security issues"""
    results = {
        'timestamp': timestamp(),
        'issues': [],
        'recommendations': []
    }
    
    torrc = Path('/etc/tor/torrc')
    if not torrc.exists():
        results['issues'].append({
            'severity': 'critical',
            'type': 'missing_config',
            'description': 'Tor configuration file not found'
        })
        return results
    
    try:
        content = torrc.read_text()
        
        # Check for HiddenService configuration
        if 'HiddenServiceDir' not in content:
            results['issues'].append({
                'severity': 'high',
                'type': 'missing_hidden_service',
                'description': 'HiddenService not configured'
            })
        
        # Check for version
        if 'HiddenServiceVersion 3' not in content:
            results['recommendations'].append({
                'type': 'version_upgrade',
                'description': 'Use HiddenServiceVersion 3 (v3 onions)'
            })
        
        # Check for safe logging
        if 'SafeLogging 0' in content:
            results['issues'].append({
                'severity': 'medium',
                'type': 'unsafe_logging',
                'description': 'SafeLogging disabled - may leak sensitive info',
                'recommendation': 'Enable SafeLogging'
            })
        
        # Check for control port exposure
        if 'ControlPort 0.0.0.0' in content:
            results['issues'].append({
                'severity': 'high',
                'type': 'exposed_control',
                'description': 'Tor control port exposed on all interfaces',
                'recommendation': 'Bind ControlPort to 127.0.0.1'
            })
        
    except Exception as e:
        results['issues'].append({
            'severity': 'low',
            'type': 'scan_error',
            'description': f'Error reading torrc: {e}'
        })
    
    return results


def run_nikto_scan(target: str = '127.0.0.1:8080') -> Dict:
    """Run Nikto web vulnerability scanner"""
    results = {
        'timestamp': timestamp(),
        'vulnerabilities': [],
        'warnings': [],
        'info': []
    }
    
    nikto_bin = shutil.which('nikto')
    if not nikto_bin:
        results['info'].append({
            'message': 'Nikto not installed. Install with: apt-get install nikto'
        })
        return results
    
    try:
        cmd = f"{shlex.quote(nikto_bin)} -h http://{shlex.quote(target)} -Format json -output -"
        result = run_cmd(cmd, timeout=600)
        
        if result.returncode == 0 and result.stdout:
            try:
                nikto_data = json.loads(result.stdout)
                if 'vulnerabilities' in nikto_data:
                    results['vulnerabilities'] = nikto_data['vulnerabilities']
            except json.JSONDecodeError:
                # Parse text output if JSON fails
                for line in result.stdout.split('\n'):
                    if 'OSVDB' in line or 'Vulnerability' in line:
                        results['vulnerabilities'].append({
                            'description': line.strip()
                        })
    except Exception as e:
        results['warnings'].append({
            'message': f'Nikto scan error: {e}'
        })
    
    return results


def run_ssl_scan(target: str = '127.0.0.1:8080') -> Dict:
    """Run SSL/TLS configuration scan"""
    results = {
        'timestamp': timestamp(),
        'issues': [],
        'recommendations': []
    }
    
    # Check if SSL is configured (for future HTTPS over Tor)
    # This is a placeholder for when HTTPS is implemented
    
    return results


def check_dependencies() -> Dict:
    """Check for outdated or vulnerable dependencies"""
    results = {
        'timestamp': timestamp(),
        'outdated': [],
        'vulnerable': []
    }
    
    # Check package versions
    packages = ['nginx', 'tor', 'openssl', 'libssl']
    
    for package in packages:
        result = run_cmd(f'dpkg -l {package} 2>/dev/null | grep ^ii', capture=True)
        if result.returncode == 0:
            # Extract version
            parts = result.stdout.split()
            if len(parts) >= 3:
                version = parts[2]
                # In production, check against CVE database
                results['outdated'].append({
                    'package': package,
                    'version': version,
                    'status': 'current'  # Would check against latest
                })
    
    return results


def scan_logs_for_attacks() -> Dict:
    """Scan logs for attack patterns"""
    results = {
        'timestamp': timestamp(),
        'attacks_detected': [],
        'suspicious_activity': []
    }
    
    attack_patterns = [
        (r'union.*select', 'SQL_INJECTION'),
        (r'<script', 'XSS'),
        (r'\.\./', 'PATH_TRAVERSAL'),
        (r'exec\(|eval\(|system\(', 'COMMAND_INJECTION'),
        (r'\.\.\\', 'PATH_TRAVERSAL_WIN'),
    ]
    
    nginx_log = Path('/var/log/nginx/access.log')
    if nginx_log.exists():
        try:
            with open(nginx_log, 'r') as f:
                lines = f.readlines()[-10000:]  # Last 10k lines
            
            for line in lines:
                for pattern, attack_type in attack_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        results['attacks_detected'].append({
                            'type': attack_type,
                            'log_line': line.strip()[:200],  # Truncate
                            'timestamp': timestamp()
                        })
                        break
        except Exception as e:
            results['suspicious_activity'].append({
                'type': 'scan_error',
                'message': str(e)
            })
    
    return results


def comprehensive_scan() -> Dict:
    """Run comprehensive security scan"""
    if not is_root():
        print('Root privileges required for full scan')
        return {}
    
    print('Starting comprehensive security scan...')
    
    scan_results = {
        'scan_timestamp': timestamp(),
        'port_scan': scan_ports(),
        'file_permissions': scan_file_permissions(),
        'nginx_config': scan_nginx_config(),
        'tor_config': scan_tor_config(),
        'dependencies': check_dependencies(),
        'log_analysis': scan_logs_for_attacks()
    }
    
    # Run Nikto if target available
    hs_port = detect_hidden_service_port()
    if hs_port:
        print(f'Running Nikto scan against {hs_port}...')
        scan_results['nikto'] = run_nikto_scan(hs_port)
    
    # Calculate risk score
    risk_score = calculate_risk_score(scan_results)
    scan_results['risk_score'] = risk_score
    
    # Save results
    SCAN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    result_file = SCAN_RESULTS_DIR / f'scan_{ts}.json'
    result_file.write_text(json.dumps(scan_results, indent=2))
    
    print(f'Scan complete. Results saved to {result_file}')
    print(f'Overall risk score: {risk_score}/100')
    
    return scan_results


def calculate_risk_score(scan_results: Dict) -> int:
    """Calculate overall risk score (0-100, higher is worse)"""
    score = 0
    
    # Port scan issues
    port_vulns = scan_results.get('port_scan', {}).get('vulnerabilities', [])
    for vuln in port_vulns:
        if vuln.get('severity') == 'high':
            score += 10
        elif vuln.get('severity') == 'medium':
            score += 5
    
    # File permission issues
    perm_issues = scan_results.get('file_permissions', {}).get('issues', [])
    for issue in perm_issues:
        if issue.get('severity') == 'high':
            score += 15
        elif issue.get('severity') == 'medium':
            score += 8
    
    # Nginx config issues
    nginx_issues = scan_results.get('nginx_config', {}).get('issues', [])
    for issue in nginx_issues:
        if issue.get('severity') == 'high':
            score += 12
        elif issue.get('severity') == 'medium':
            score += 6
    
    # Tor config issues
    tor_issues = scan_results.get('tor_config', {}).get('issues', [])
    for issue in tor_issues:
        if issue.get('severity') == 'critical':
            score += 20
        elif issue.get('severity') == 'high':
            score += 15
    
    # Attacks detected
    attacks = scan_results.get('log_analysis', {}).get('attacks_detected', [])
    score += min(len(attacks) * 2, 20)  # Cap at 20
    
    return min(100, score)


def detect_hidden_service_port() -> Optional[str]:
    """Detect hidden service port from torrc"""
    torrc = Path('/etc/tor/torrc')
    if not torrc.exists():
        return None
    
    try:
        content = torrc.read_text()
        match = re.search(r'HiddenServicePort\s+\d+\s+([\d.]+:\d+)', content)
        if match:
            return match.group(1)
    except:
        pass
    
    return '127.0.0.1:8080'  # Default


def generate_report(scan_results: Dict) -> str:
    """Generate human-readable security report"""
    report = []
    report.append("=" * 80)
    report.append("ONIONSITE SECURITY SCAN REPORT")
    report.append("=" * 80)
    report.append(f"Scan Date: {scan_results.get('scan_timestamp', 'Unknown')}")
    report.append(f"Risk Score: {scan_results.get('risk_score', 0)}/100")
    report.append("")
    
    # Port scan
    port_scan = scan_results.get('port_scan', {})
    if port_scan.get('vulnerabilities'):
        report.append("PORT SCAN ISSUES:")
        for vuln in port_scan['vulnerabilities']:
            report.append(f"  [{vuln.get('severity', 'unknown').upper()}] {vuln.get('description', '')}")
        report.append("")
    
    # File permissions
    perm_scan = scan_results.get('file_permissions', {})
    if perm_scan.get('issues'):
        report.append("FILE PERMISSION ISSUES:")
        for issue in perm_scan['issues']:
            report.append(f"  [{issue.get('severity', 'unknown').upper()}] {issue.get('file', '')}: {issue.get('description', '')}")
        report.append("")
    
    # Nginx config
    nginx_scan = scan_results.get('nginx_config', {})
    if nginx_scan.get('issues'):
        report.append("NGINX CONFIGURATION ISSUES:")
        for issue in nginx_scan['issues']:
            report.append(f"  [{issue.get('severity', 'unknown').upper()}] {issue.get('description', '')}")
        report.append("")
    
    # Tor config
    tor_scan = scan_results.get('tor_config', {})
    if tor_scan.get('issues'):
        report.append("TOR CONFIGURATION ISSUES:")
        for issue in tor_scan['issues']:
            report.append(f"  [{issue.get('severity', 'unknown').upper()}] {issue.get('description', '')}")
        report.append("")
    
    # Attacks detected
    log_scan = scan_results.get('log_analysis', {})
    if log_scan.get('attacks_detected'):
        report.append(f"ATTACKS DETECTED: {len(log_scan['attacks_detected'])}")
        attack_types = {}
        for attack in log_scan['attacks_detected']:
            attack_type = attack.get('type', 'UNKNOWN')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        for attack_type, count in attack_types.items():
            report.append(f"  {attack_type}: {count}")
        report.append("")
    
    report.append("=" * 80)
    
    return "\n".join(report)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Scanner')
    parser.add_argument('--scan', action='store_true', help='Run comprehensive scan')
    parser.add_argument('--ports', action='store_true', help='Scan ports only')
    parser.add_argument('--config', action='store_true', help='Scan configurations only')
    parser.add_argument('--nikto', action='store_true', help='Run Nikto scan')
    parser.add_argument('--report', action='store_true', help='Generate text report')
    parser.add_argument('--target', type=str, default='127.0.0.1:8080', help='Target for scans')
    
    args = parser.parse_args()
    
    if args.scan:
        results = comprehensive_scan()
        if args.report:
            print(generate_report(results))
    elif args.ports:
        results = scan_ports()
        print(json.dumps(results, indent=2))
    elif args.config:
        nginx_results = scan_nginx_config()
        tor_results = scan_tor_config()
        print(json.dumps({'nginx': nginx_results, 'tor': tor_results}, indent=2))
    elif args.nikto:
        results = run_nikto_scan(args.target)
        print(json.dumps(results, indent=2))
    else:
        parser.print_help()

