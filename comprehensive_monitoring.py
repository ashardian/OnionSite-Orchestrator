#!/usr/bin/env python3
"""
Comprehensive Monitoring and Alerting System
Real-time monitoring, anomaly detection, and multi-channel alerting
"""

import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import statistics

# Configuration
MONITORING_DIR = Path('/var/lib/onionsite-monitoring')
METRICS_DB = MONITORING_DIR / 'metrics.json'
ALERT_RULES = MONITORING_DIR / 'alert-rules.json'
ALERT_LOG = Path('/var/log/onionsite-monitoring/alerts.log')
METRICS_LOG = Path('/var/log/onionsite-monitoring/metrics.log')
DASHBOARD_DATA = MONITORING_DIR / 'dashboard.json'

# Alert thresholds
THRESHOLDS = {
    'cpu_usage': 80.0,
    'memory_usage': 85.0,
    'disk_usage': 90.0,
    'error_rate': 10,  # errors per minute
    'response_time': 2.0,  # seconds
    'connection_count': 1000,
    'failed_logins': 5,
    'tor_restarts': 3,
    'nginx_restarts': 3
}

# Alert channels
ALERT_CHANNELS = {
    'webhook': None,
    'email': None,
    'syslog': True,
    'file': True
}


def is_root():
    return os.geteuid() == 0


def timestamp():
    return datetime.utcnow().isoformat() + 'Z'


def log(message: str, level: str = 'INFO'):
    """Log monitoring events"""
    entry = f"[{timestamp()}] [{level}] {message}\n"
    try:
        METRICS_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(METRICS_LOG, 'a') as f:
            f.write(entry)
    except Exception:
        pass


def run_cmd(cmd: str, capture: bool = True, timeout: Optional[int] = 10) -> subprocess.CompletedProcess:
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


def collect_system_metrics() -> Dict:
    """Collect system performance metrics"""
    metrics = {
        'timestamp': timestamp(),
        'cpu': {},
        'memory': {},
        'disk': {},
        'network': {},
        'services': {}
    }
    
    # CPU usage
    result = run_cmd("top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'", capture=True)
    try:
        metrics['cpu']['usage'] = float(result.stdout.strip())
    except:
        metrics['cpu']['usage'] = 0.0
    
    # Memory usage
    result = run_cmd("free | grep Mem | awk '{printf \"%.2f\", $3/$2 * 100.0}'", capture=True)
    try:
        metrics['memory']['usage'] = float(result.stdout.strip())
    except:
        metrics['memory']['usage'] = 0.0
    
    # Disk usage
    result = run_cmd("df -h / | tail -1 | awk '{print $5}' | sed 's/%//'", capture=True)
    try:
        metrics['disk']['usage'] = float(result.stdout.strip())
    except:
        metrics['disk']['usage'] = 0.0
    
    # Network stats
    result = run_cmd("ss -s", capture=True)
    if result.returncode == 0:
        # Extract connection counts
        tcp_match = re.search(r'TCP:\s+(\d+)', result.stdout)
        if tcp_match:
            metrics['network']['tcp_connections'] = int(tcp_match.group(1))
    
    # Service status
    for service in ['tor', 'nginx', 'fail2ban']:
        result = run_cmd(f'systemctl is-active {service}', capture=True)
        metrics['services'][service] = {
            'active': result.returncode == 0,
            'status': result.stdout.strip()
        }
    
    return metrics


def collect_tor_metrics() -> Dict:
    """Collect Tor-specific metrics"""
    metrics = {
        'timestamp': timestamp(),
        'circuits': {},
        'bandwidth': {},
        'hidden_service': {}
    }
    
    # Check Tor control port (if accessible)
    result = run_cmd('systemctl status tor@default || systemctl status tor', capture=True)
    metrics['tor_running'] = result.returncode == 0
    
    # Check hidden service hostname
    hostname_file = Path('/var/lib/tor/onion_service/hostname')
    if hostname_file.exists():
        metrics['hidden_service']['hostname'] = hostname_file.read_text().strip()
        metrics['hidden_service']['exists'] = True
    else:
        metrics['hidden_service']['exists'] = False
    
    # Check Tor logs for errors
    tor_log = Path('/var/log/tor/tor.log')
    if tor_log.exists():
        try:
            with open(tor_log, 'r') as f:
                lines = f.readlines()[-100:]  # Last 100 lines
                error_count = sum(1 for line in lines if 'error' in line.lower() or 'warn' in line.lower())
                metrics['tor_errors'] = error_count
        except:
            pass
    
    return metrics


def collect_nginx_metrics() -> Dict:
    """Collect Nginx-specific metrics"""
    metrics = {
        'timestamp': timestamp(),
        'requests': {},
        'errors': {},
        'response_times': []
    }
    
    access_log = Path('/var/log/nginx/access.log')
    error_log = Path('/var/log/nginx/error.log')
    
    if access_log.exists():
        try:
            with open(access_log, 'r') as f:
                lines = f.readlines()[-1000:]  # Last 1000 lines
            
            # Count requests by status code
            status_counts = defaultdict(int)
            response_times = []
            
            for line in lines:
                # Parse common log format
                match = re.search(r'"\s+(\d{3})\s+', line)
                if match:
                    status = match.group(1)
                    status_counts[status] += 1
                
                # Extract response time if available
                time_match = re.search(r'(\d+\.\d+)$', line)
                if time_match:
                    response_times.append(float(time_match.group(1)))
            
            metrics['requests']['total'] = len(lines)
            metrics['requests']['by_status'] = dict(status_counts)
            metrics['errors']['4xx'] = status_counts.get('4', 0) + status_counts.get('5', 0)
            metrics['errors']['5xx'] = status_counts.get('5', 0)
            
            if response_times:
                metrics['response_times'] = {
                    'avg': statistics.mean(response_times),
                    'max': max(response_times),
                    'min': min(response_times),
                    'p95': sorted(response_times)[int(len(response_times) * 0.95)] if len(response_times) > 20 else max(response_times)
                }
        except Exception as e:
            log(f'Error parsing nginx logs: {e}', 'ERROR')
    
    if error_log.exists():
        try:
            with open(error_log, 'r') as f:
                error_lines = f.readlines()[-100:]
                metrics['errors']['log_entries'] = len([l for l in error_lines if 'error' in l.lower()])
        except:
            pass
    
    return metrics


def detect_anomalies(current_metrics: Dict, historical_metrics: List[Dict]) -> List[Dict]:
    """Detect anomalies using statistical analysis"""
    anomalies = []
    
    if not historical_metrics:
        return anomalies
    
    # Calculate baseline statistics
    cpu_values = [m.get('cpu', {}).get('usage', 0) for m in historical_metrics[-100:]]
    memory_values = [m.get('memory', {}).get('usage', 0) for m in historical_metrics[-100:]]
    
    if cpu_values:
        cpu_mean = statistics.mean(cpu_values)
        cpu_std = statistics.stdev(cpu_values) if len(cpu_values) > 1 else 0
        current_cpu = current_metrics.get('cpu', {}).get('usage', 0)
        
        if current_cpu > cpu_mean + 2 * cpu_std and current_cpu > THRESHOLDS['cpu_usage']:
            anomalies.append({
                'type': 'high_cpu',
                'severity': 'warning' if current_cpu < 90 else 'critical',
                'value': current_cpu,
                'threshold': THRESHOLDS['cpu_usage'],
                'message': f'CPU usage abnormally high: {current_cpu:.1f}%'
            })
    
    if memory_values:
        memory_mean = statistics.mean(memory_values)
        memory_std = statistics.stdev(memory_values) if len(memory_values) > 1 else 0
        current_memory = current_metrics.get('memory', {}).get('usage', 0)
        
        if current_memory > memory_mean + 2 * memory_std and current_memory > THRESHOLDS['memory_usage']:
            anomalies.append({
                'type': 'high_memory',
                'severity': 'warning' if current_memory < 95 else 'critical',
                'value': current_memory,
                'threshold': THRESHOLDS['memory_usage'],
                'message': f'Memory usage abnormally high: {current_memory:.1f}%'
            })
    
    # Check service status
    services = current_metrics.get('services', {})
    for service, status in services.items():
        if not status.get('active', False):
            anomalies.append({
                'type': 'service_down',
                'severity': 'critical',
                'service': service,
                'message': f'Service {service} is not active'
            })
    
    # Check error rates
    nginx_metrics = collect_nginx_metrics()
    error_rate = nginx_metrics.get('errors', {}).get('5xx', 0)
    if error_rate > THRESHOLDS['error_rate']:
        anomalies.append({
            'type': 'high_error_rate',
            'severity': 'warning' if error_rate < 50 else 'critical',
            'value': error_rate,
            'threshold': THRESHOLDS['error_rate'],
            'message': f'High error rate detected: {error_rate} 5xx errors'
        })
    
    return anomalies


def send_alert(alert: Dict, channels: Dict = None):
    """Send alert through configured channels"""
    if channels is None:
        channels = ALERT_CHANNELS
    
    alert_entry = {
        'timestamp': timestamp(),
        'alert': alert
    }
    
    # Log to file
    if channels.get('file', True):
        try:
            ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
            with open(ALERT_LOG, 'a') as f:
                f.write(json.dumps(alert_entry) + '\n')
        except:
            pass
    
    # Send to webhook
    if channels.get('webhook'):
        try:
            payload = json.dumps({
                'text': f"[{alert.get('severity', 'INFO').upper()}] {alert.get('message', 'Alert')}",
                'timestamp': timestamp()
            })
            cmd = f"curl -s -X POST -H 'Content-Type: application/json' -d {shlex.quote(payload)} {shlex.quote(channels['webhook'])}"
            run_cmd(cmd, capture=True)
        except:
            pass
    
    # Send email
    if channels.get('email'):
        try:
            subject = f"OnionSite Alert: {alert.get('type', 'Unknown')}"
            body = json.dumps(alert, indent=2)
            cmd = f"echo {shlex.quote(body)} | mail -s {shlex.quote(subject)} {shlex.quote(channels['email'])}"
            run_cmd(cmd, capture=True)
        except:
            pass
    
    # Syslog
    if channels.get('syslog', True):
        try:
            severity_map = {'critical': 'crit', 'warning': 'warning', 'info': 'info'}
            level = severity_map.get(alert.get('severity', 'info'), 'info')
            message = alert.get('message', 'Alert')
            run_cmd(f"logger -p {level} 'OnionSite: {message}'", capture=True)
        except:
            pass
    
    log(f"Alert sent: {alert.get('message', 'Unknown')}")


def update_dashboard(metrics: Dict, anomalies: List[Dict]):
    """Update dashboard data"""
    dashboard_data = {
        'last_update': timestamp(),
        'metrics': metrics,
        'anomalies': anomalies,
        'services': {
            'tor': metrics.get('services', {}).get('tor', {}).get('active', False),
            'nginx': metrics.get('services', {}).get('nginx', {}).get('active', False),
            'fail2ban': metrics.get('services', {}).get('fail2ban', {}).get('active', False)
        },
        'health_score': calculate_health_score(metrics, anomalies)
    }
    
    try:
        DASHBOARD_DATA.parent.mkdir(parents=True, exist_ok=True)
        with open(DASHBOARD_DATA, 'w') as f:
            json.dump(dashboard_data, f, indent=2)
    except Exception as e:
        log(f'Failed to update dashboard: {e}', 'ERROR')


def calculate_health_score(metrics: Dict, anomalies: List[Dict]) -> int:
    """Calculate overall health score (0-100)"""
    score = 100
    
    # Deduct for anomalies
    for anomaly in anomalies:
        severity = anomaly.get('severity', 'info')
        if severity == 'critical':
            score -= 20
        elif severity == 'warning':
            score -= 10
    
    # Deduct for high resource usage
    cpu = metrics.get('cpu', {}).get('usage', 0)
    memory = metrics.get('memory', {}).get('usage', 0)
    disk = metrics.get('disk', {}).get('usage', 0)
    
    if cpu > 90:
        score -= 15
    elif cpu > 80:
        score -= 10
    
    if memory > 95:
        score -= 15
    elif memory > 85:
        score -= 10
    
    if disk > 95:
        score -= 20
    elif disk > 90:
        score -= 10
    
    # Deduct for service failures
    services = metrics.get('services', {})
    for service, status in services.items():
        if not status.get('active', False):
            score -= 25
    
    return max(0, min(100, score))


def store_metrics(metrics: Dict):
    """Store metrics in database"""
    try:
        MONITORING_DIR.mkdir(parents=True, exist_ok=True)
        
        if METRICS_DB.exists():
            with open(METRICS_DB, 'r') as f:
                all_metrics = json.load(f)
        else:
            all_metrics = []
        
        all_metrics.append(metrics)
        
        # Keep only last 10000 entries
        if len(all_metrics) > 10000:
            all_metrics = all_metrics[-10000:]
        
        with open(METRICS_DB, 'w') as f:
            json.dump(all_metrics, f, indent=2)
    except Exception as e:
        log(f'Failed to store metrics: {e}', 'ERROR')


def monitoring_loop(interval: int = 60, webhook: Optional[str] = None, email: Optional[str] = None):
    """Main monitoring loop"""
    log('Starting monitoring loop...')
    
    channels = ALERT_CHANNELS.copy()
    if webhook:
        channels['webhook'] = webhook
    if email:
        channels['email'] = email
    
    historical_metrics = []
    
    try:
        while True:
            # Collect metrics
            system_metrics = collect_system_metrics()
            tor_metrics = collect_tor_metrics()
            nginx_metrics = collect_nginx_metrics()
            
            # Combine metrics
            combined_metrics = {
                **system_metrics,
                'tor': tor_metrics,
                'nginx': nginx_metrics
            }
            
            # Store metrics
            store_metrics(combined_metrics)
            historical_metrics.append(combined_metrics)
            
            # Keep only last 1000 for anomaly detection
            if len(historical_metrics) > 1000:
                historical_metrics = historical_metrics[-1000:]
            
            # Detect anomalies
            anomalies = detect_anomalies(combined_metrics, historical_metrics)
            
            # Send alerts for new anomalies
            for anomaly in anomalies:
                if anomaly.get('severity') in ['warning', 'critical']:
                    send_alert(anomaly, channels)
            
            # Update dashboard
            update_dashboard(combined_metrics, anomalies)
            
            log(f'Monitoring cycle complete. Health score: {calculate_health_score(combined_metrics, anomalies)}')
            
            time.sleep(interval)
    except KeyboardInterrupt:
        log('Monitoring stopped by user')
    except Exception as e:
        log(f'Monitoring error: {e}', 'ERROR')
        raise


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Comprehensive Monitoring System')
    parser.add_argument('--monitor', action='store_true', help='Start monitoring loop')
    parser.add_argument('--interval', type=int, default=60, help='Monitoring interval in seconds')
    parser.add_argument('--webhook', type=str, help='Webhook URL for alerts')
    parser.add_argument('--email', type=str, help='Email address for alerts')
    parser.add_argument('--metrics', action='store_true', help='Collect and display current metrics')
    parser.add_argument('--dashboard', action='store_true', help='Display dashboard data')
    
    args = parser.parse_args()
    
    if args.monitor:
        monitoring_loop(interval=args.interval, webhook=args.webhook, email=args.email)
    elif args.metrics:
        system_metrics = collect_system_metrics()
        tor_metrics = collect_tor_metrics()
        nginx_metrics = collect_nginx_metrics()
        combined = {**system_metrics, 'tor': tor_metrics, 'nginx': nginx_metrics}
        print(json.dumps(combined, indent=2))
    elif args.dashboard:
        if DASHBOARD_DATA.exists():
            with open(DASHBOARD_DATA, 'r') as f:
                dashboard = json.load(f)
            print(json.dumps(dashboard, indent=2))
        else:
            print('Dashboard data not available. Run --monitor first.')
    else:
        parser.print_help()

