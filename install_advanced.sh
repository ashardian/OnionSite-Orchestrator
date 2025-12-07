#!/usr/bin/env bash
# Advanced OnionSite Orchestrator Installation Script
# Installs all components and sets up automated services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/onionsite-orchestrator"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

install_dependencies() {
    log "Installing dependencies..."
    apt-get update -qq
    apt-get install -y \
        python3 \
        python3-pip \
        tor \
        nginx \
        ufw \
        fail2ban \
        nftables \
        apparmor \
        apparmor-utils \
        gpg \
        curl \
        jq \
        mailutils \
        nikto \
        || warn "Some packages may have failed to install"
}

install_scripts() {
    log "Installing scripts to $INSTALL_DIR..."
    
    # Copy Python scripts
    for script in advanced_security_module.py automated_backup_rotation.py \
                  comprehensive_monitoring.py security_scanner.py unified_orchestrator.py; do
        if [ -f "$SCRIPT_DIR/$script" ]; then
            cp "$SCRIPT_DIR/$script" "$INSTALL_DIR/"
            chmod +x "$INSTALL_DIR/$script"
            log "Installed $script"
        else
            warn "$script not found, skipping"
        fi
    done
    
    # Copy bash script if exists
    if [ -f "$SCRIPT_DIR/onionsite-orchestrator.sh" ]; then
        cp "$SCRIPT_DIR/onionsite-orchestrator.sh" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/onionsite-orchestrator.sh"
        log "Installed onionsite-orchestrator.sh"
    fi
}

setup_directories() {
    log "Creating directories..."
    mkdir -p /var/backups/onionsite/{keys,configs,encrypted}
    mkdir -p /var/lib/onionsite-monitoring
    mkdir -p /var/lib/onionsite-security/{scans,ids-rules}
    mkdir -p /var/log/onionsite-orchestrator
    mkdir -p /var/log/onionsite-security
    mkdir -p /var/log/onionsite-monitoring
    mkdir -p /var/log/onionsite-backup
    mkdir -p "$CONFIG_DIR"
    
    log "Directories created"
}

create_config() {
    log "Creating default configuration..."
    
    if [ ! -f "$CONFIG_DIR/config.json" ]; then
        cat > "$CONFIG_DIR/config.json" <<'EOF'
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
    "gpg_recipient": null,
    "auto_rotate_keys": false,
    "rotation_days": 90
  },
  "monitoring": {
    "enabled": true,
    "interval": 60,
    "webhook": null,
    "email": null
  },
  "scanning": {
    "auto_scan": true,
    "scan_interval_hours": 24
  }
}
EOF
        log "Default configuration created at $CONFIG_DIR/config.json"
    else
        warn "Configuration already exists, skipping"
    fi
}

main() {
    log "=========================================="
    log "OnionSite Orchestrator - Advanced Edition"
    log "Installation Script"
    log "=========================================="
    
    require_root
    
    install_dependencies
    install_scripts
    setup_directories
    create_config
    
    log ""
    log "=========================================="
    log "Installation Complete!"
    log "=========================================="
    log ""
    log "Next steps:"
    log "1. Deploy base OnionSite:"
    log "   sudo $INSTALL_DIR/onionsite-orchestrator.sh --install"
    log ""
    log "2. Deploy complete enterprise-grade stack:"
    log "   sudo python3 $INSTALL_DIR/unified_orchestrator.py --deploy"
    log ""
    log "3. Check status:"
    log "   sudo python3 $INSTALL_DIR/unified_orchestrator.py --status"
    log ""
    log "Configuration file: $CONFIG_DIR/config.json"
    log ""
}

main "$@"

