#!/usr/bin/env bash
# =============================================================
# OnionSite-Orchestrator v3.1 - Self-Healing Edition (Full)
# Author: Mr Gamer
# Target: Debian/Ubuntu/Parrot (systemd)
# Purpose: Install, configure and self-heal Tor Hidden Service + nginx
# Version: 2025-11-02
# =============================================================
set -euo pipefail
IFS=$'\n\t'

# -----------------------
# Configurable defaults
# -----------------------
LOG="/var/log/onionsite-orchestrator.log"
WEB_ROOT="/var/www/onion_site"
NGINX_SITE_CONF="/etc/nginx/sites-available/onion_site"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/onion_site"
NGINX_BIND="127.0.0.1"
NGINX_PORT="8080"
HSDIR="/var/lib/tor/onion_service"
TORRC="/etc/tor/torrc"
TOR_USER_DEFAULT="debian-tor"
BACKUP_DIR="/var/backups/onionsite"
WATCHDOG_SERVICE="/etc/systemd/system/onionsite-tor-watchdog.service"
WATCHDOG_TIMER="/etc/systemd/system/onionsite-tor-watchdog.timer"
WATCHDOG_SCRIPT="/usr/local/bin/onionsite-orchestrator-watchdog.sh"

# CLI flags
DRY_RUN=false
VERBOSE=false
AUTO_YES=false

# -----------------------
# Helpers / logging
# -----------------------
timestamp(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log(){ mkdir -p "$(dirname "$LOG")"; echo "[$(timestamp)] [INFO] $*" | tee -a "$LOG"; }
warn(){ echo "[$(timestamp)] [WARN] $*" | tee -a "$LOG" >&2; }
err(){ echo "[$(timestamp)] [ERROR] $*" | tee -a "$LOG" >&2; }
die(){ err "$*"; exit 1; }

run(){
  if $DRY_RUN; then
    log "[DRY-RUN] $*"
    return 0
  fi
  if $VERBOSE; then
    log "RUN: $*"
    bash -x -c "$*"
  else
    bash -c "$@" &>>"$LOG" || { err "Command failed: $* (see $LOG)"; return 1; }
  fi
}

require_root(){ if [ "$(id -u)" -ne 0 ]; then die "Please run as root (sudo)."; fi; }
confirm_or_abort(){
  if $AUTO_YES; then return 0; fi
  read -rp "$1 [y/N]: " yn
  case "$yn" in [Yy]*) return 0;; *) die "Aborted by user.";; esac
}

# -----------------------
# Detect which Tor service to use
# -----------------------
detect_tor_service(){
  # If tor@default.service exists and enabled -> use it, else prefer tor@default if active; else tor
  if systemctl list-unit-files | grep -q '^tor@default.service' && systemctl is-enabled --quiet tor@default 2>/dev/null; then
    echo "tor@default"
    return
  fi
  # if tor@default active now
  if systemctl is-active --quiet tor@default 2>/dev/null; then
    echo "tor@default"
    return
  fi
  # else if tor.service exists/active
  if systemctl list-unit-files | grep -q '^tor.service' || systemctl is-active --quiet tor 2>/dev/null; then
    echo "tor"
    return
  fi
  # fallback
  echo "tor"
}

# -----------------------
# Switch to tor@default (if multi-instance tor is in use)
# -----------------------
ensure_tor_default_instance(){
  require_root
  local current
  current=$(detect_tor_service)
  log "Detected Tor service: $current"
  # If current is tor (multi-instance) we prefer tor@default for hidden services
  if [ "$current" = "tor" ]; then
    log "Attempting to switch to tor@default (recommended for HiddenService handling)..."
    # Stop and disable master tor.service
    run "systemctl stop tor || true"
    run "systemctl disable tor || true"
    # Enable and start tor@default
    run "systemctl enable tor@default || true"
    run "systemctl daemon-reload || true"
    run "systemctl start tor@default || true"
    sleep 2
    if systemctl is-active --quiet tor@default; then
      log "Switched to tor@default successfully."
      return 0
    else
      warn "tor@default failed to start. Will continue using 'tor' if available."
      return 1
    fi
  fi
  # If already tor@default, ensure it's running
  if [ "$current" = "tor@default" ]; then
    if ! systemctl is-active --quiet tor@default; then
      run "systemctl start tor@default || true"
    fi
    log "Using existing tor@default."
  fi
}

# -----------------------
# Install prerequisites
# -----------------------
install_packages(){
  require_root
  log "Installing required packages (apt update && install)..."
  run "apt-get update -y"
  local pkgs=(tor nginx ufw openssl rsync curl)
  for p in "${pkgs[@]}"; do
    if dpkg -s "$p" &>/dev/null; then
      log "Package $p already installed."
    else
      log "Installing $p..."
      run "DEBIAN_FRONTEND=noninteractive apt-get install -y $p"
    fi
  done
}

# -----------------------
# Prepare webroot & nginx config
# -----------------------
prepare_webroot(){
  require_root
  log "Preparing web root at $WEB_ROOT"
  run "mkdir -p '$WEB_ROOT'"
  cat > "$WEB_ROOT/index.html" <<'HTML'
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Onion Site</title></head>
<body style="background:#000;color:#0f0;font-family:monospace;text-align:center;padding-top:10%">
<h1>✅ Onion Hidden Service</h1>
<p>Served via Tor</p>
</body>
</html>
HTML
  run "chown -R www-data:www-data '$WEB_ROOT' || true"
  run "chmod -R 755 '$WEB_ROOT' || true"
  log "Web root created."
}

write_nginx_site(){
  require_root
  log "Writing nginx site config -> $NGINX_SITE_CONF"
  cat > "$NGINX_SITE_CONF" <<EOF
server {
    listen ${NGINX_BIND}:${NGINX_PORT} default_server;
    listen [::1]:${NGINX_PORT} default_server;
    server_name localhost;
    root ${WEB_ROOT};
    index index.html;
    server_tokens off;
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
  run "ln -sf $NGINX_SITE_CONF $NGINX_SITE_LINK || true"
  # Remove default to avoid 0.0.0.0:80 binding
  if [ -f /etc/nginx/sites-enabled/default ]; then
    run "rm -f /etc/nginx/sites-enabled/default || true"
  fi
  # Test and restart nginx
  if run "nginx -t"; then
    run "systemctl restart nginx"
    run "systemctl enable nginx"
    log "nginx configured and restarted."
  else
    die "nginx -t failed. Inspect /var/log/nginx/error.log"
  fi
}

# -----------------------
# Ensure HiddenServiceDir and torrc entry
# -----------------------
ensure_hidden_service(){
  require_root
  local svc; svc=$(detect_tor_service)
  log "Ensuring HiddenService at $HSDIR (tor service: $svc)"
  run "mkdir -p '$HSDIR'"
  run "chown -R ${TOR_USER_DEFAULT}:$TOR_USER_DEFAULT '$HSDIR' 2>/dev/null || true"
  run "chmod 700 '$HSDIR' || true"

  # idempotent append to torrc: ensure marker present
  local marker="HiddenServiceDir $HSDIR/"
  if ! grep -qF "$marker" "$TORRC" 2>/dev/null; then
    log "Adding HiddenService directives to $TORRC"
    cat >> "$TORRC" <<TORRC_EOF

# Added by OnionSite-Orchestrator
HiddenServiceDir $HSDIR/
HiddenServiceVersion 3
HiddenServicePort 80 ${NGINX_BIND}:${NGINX_PORT}
TORRC_EOF
  else
    log "torrc already contains HiddenService for $HSDIR"
  fi

  # Restart correct tor service
  if systemctl is-active --quiet tor@default 2>/dev/null; then
    run "systemctl restart tor@default"
  else
    run "systemctl restart tor || true"
  fi

  # wait for hostname
  log "Waiting up to 30s for onion hostname generation..."
  local i=0
  while [ $i -lt 30 ]; do
    if [ -f "$HSDIR/hostname" ]; then
      local onion; onion=$(cat "$HSDIR/hostname")
      log "Hidden service hostname: $onion"
      echo "$onion"
      return 0
    fi
    sleep 1
    i=$((i+1))
  done
  warn "Timed out waiting for .onion hostname. Inspect Tor logs."
  return 1
}

# -----------------------
# Firewall
# -----------------------
configure_firewall(){
  require_root
  log "Configuring UFW: deny incoming by default, allow outgoing and SSH"
  run "ufw --force reset"
  run "ufw default deny incoming"
  run "ufw default allow outgoing"
  run "ufw allow OpenSSH"
  # do NOT open 8080 publicly (nginx on loopback)
  run "ufw --force enable"
  log "UFW configured."
}

# -----------------------
# Health check and status
# -----------------------
action_status(){
  require_root
  log "=== STATUS SUMMARY ==="
  local svc; svc=$(detect_tor_service)
  echo "Tor service unit: $svc"
  systemctl is-active --quiet "$svc" && echo "Tor: active" || echo "Tor: inactive"
  systemctl is-active --quiet nginx && echo "nginx: active" || echo "nginx: inactive"
  echo "nginx bind: ${NGINX_BIND}:${NGINX_PORT}"
  ss -ltn "sport = :${NGINX_PORT}" || true
  if [ -f "$HSDIR/hostname" ]; then
    echo "Onion: $(cat "$HSDIR/hostname")"
  else
    echo "Onion: (none)"
  fi
  echo "Web root: $WEB_ROOT"
  echo "Log: $LOG"
}

# -----------------------
# Backup hidden service + nginx config
# -----------------------
action_backup(){
  require_root
  run "mkdir -p '$BACKUP_DIR'"
  local ts; ts=$(date -u +"%Y%m%dT%H%M%SZ")
  local out="$BACKUP_DIR/onionsite_backup_$ts.tar.gz"
  run "tar -czf '$out' -C / $(echo "$HSDIR" | sed 's:^/::') /etc/nginx/sites-available/onion_site /etc/tor/torrc || true"
  run "chown root:root '$out' || true"
  log "Backup created: $out"
  echo "$out"
}

# -----------------------
# Rotate keys (new onion address)
# -----------------------
action_rotate_keys(){
  require_root
  confirm_or_abort "Rotate HiddenService keys and generate a new onion address? (backups will be created)"
  action_backup || true
  log "Stopping Tor service to rotate keys..."
  if systemctl list-unit-files | grep -q '^tor@default.service' && systemctl is-enabled --quiet tor@default 2>/dev/null; then
    run "systemctl stop tor@default" || true
  else
    run "systemctl stop tor" || true
  fi
  # securely remove keys
  run "shred -u ${HSDIR}/hs_ed25519_secret_key 2>/dev/null || true"
  run "rm -f ${HSDIR}/* 2>/dev/null || true"
  run "chown -R ${TOR_USER_DEFAULT}:${TOR_USER_DEFAULT} ${HSDIR} || true"
  run "chmod 700 ${HSDIR} || true"
  # start tor
  if systemctl list-unit-files | grep -q '^tor@default.service' && systemctl is-enabled --quiet tor@default 2>/dev/null; then
    run "systemctl start tor@default" || true
  else
    run "systemctl start tor" || true
  fi
  log "Waiting for new hostname..."
  local i=0
  while [ $i -lt 30 ]; do
    if [ -f "$HSDIR/hostname" ]; then
      log "New onion: $(cat $HSDIR/hostname)"
      return 0
    fi
    sleep 1
    i=$((i+1))
  done
  die "Rotation failed: hostname not created"
}

# -----------------------
# Watchdog (systemd timer + script)
# -----------------------
install_watchdog(){
  require_root
  log "Installing systemd watchdog to restart Tor if it stops..."
  cat > "$WATCHDOG_SCRIPT" <<'WDS'
#!/usr/bin/env bash
TSVC="$(systemctl list-unit-files | grep -q '^tor@default.service' && echo tor@default || echo tor)"
if ! systemctl is-active --quiet "$TSVC"; then
  logger -t onionsite "Watchdog: $TSVC inactive, restarting"
  systemctl restart "$TSVC"
fi
WDS
  run "chmod +x '$WATCHDOG_SCRIPT'"
  cat > "$WATCHDOG_SERVICE" <<SERV
[Unit]
Description=OnionSite-Orchestrator Tor Watchdog
After=network.target

[Service]
Type=oneshot
ExecStart=$WATCHDOG_SCRIPT
Nice=10
Serv
SERV
  cat > "$WATCHDOG_TIMER" <<TIMER
[Unit]
Description=OnionSite-Orchestrator Tor Watchdog Timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=$(basename "$WATCHDOG_SERVICE")

[Install]
WantedBy=timers.target
TIMER
  run "systemctl daemon-reload"
  run "systemctl enable --now $(basename "$WATCHDOG_TIMER") || true"
  log "Watchdog installed and started (systemd timer)."
}

remove_watchdog(){
  require_root
  run "systemctl disable --now $(basename "$WATCHDOG_TIMER") || true"
  run "rm -f '$WATCHDOG_SERVICE' '$WATCHDOG_TIMER' '$WATCHDOG_SCRIPT' || true"
  run "systemctl daemon-reload || true"
  log "Watchdog removed."
}

# -----------------------
# Self-heal routine
# -----------------------
self_heal(){
  require_root
  log "Running self-heal sequence..."
  # 1) ensure tor@default preferred and running
  ensure_tor_default_instance || warn "Could not fully switch to tor@default; will attempt to proceed."
  # 2) ensure permissions for HSDIR
  run "mkdir -p '$HSDIR'"
  run "chown -R ${TOR_USER_DEFAULT}:${TOR_USER_DEFAULT} '$HSDIR' 2>/dev/null || true"
  run "chmod 700 '$HSDIR' || true"
  # 3) ensure nginx config & binding
  prepare_webroot
  write_nginx_site
  # 4) ensure torrc has correct mapping
  if ! grep -qF "HiddenServiceDir $HSDIR/" "$TORRC" 2>/dev/null; then
    log "Adding HiddenService config to torrc"
    cat >> "$TORRC" <<EOF

# Added by OnionSite-Orchestrator (self-heal)
HiddenServiceDir $HSDIR/
HiddenServiceVersion 3
HiddenServicePort 80 ${NGINX_BIND}:${NGINX_PORT}
EOF
  fi
  # 5) restart tor (prefer tor@default)
  if systemctl is-active --quiet tor@default 2>/dev/null; then
    run "systemctl restart tor@default"
  else
    run "systemctl restart tor || true"
  fi
  # 6) wait for hostname
  log "Waiting for .onion hostname (30s)..."
  local i=0
  while [ $i -lt 30 ]; do
    if [ -f "$HSDIR/hostname" ]; then
      log "Self-heal: onion hostname present: $(cat "$HSDIR/hostname")"
      break
    fi
    sleep 1
    i=$((i+1))
  done
  # 7) configure firewall
  configure_firewall
  # 8) final checks
  action_status
  log "Self-heal finished."
}

# -----------------------
# CLI / Dispatcher
# -----------------------
usage(){
  cat <<EOF
OnionSite-Orchestrator v3.1 - self-healing

Usage: sudo /usr/local/bin/onionsite-orchestrator.sh [command] [--flags]

Commands:
  --install            Install packages, configure nginx & tor, deploy hidden service
  --deploy             Configure nginx & tor (assumes packages installed)
  --status             Show service status and onion hostname (if any)
  --show               Print current .onion hostname (if present)
  --backup             Backup hidden service keys + nginx config
  --rotate-keys        Rotate HiddenService keys (generate new onion)
  --watchdog-enable    Install systemd watchdog to restart Tor if it stops
  --watchdog-disable   Remove watchdog
  --self-heal          Run full self-heal routine to auto-fix common issues
  --remove             Remove site, configs and hidden keys (destructive)
  --dry-run            Show actions without executing
  --verbose            Show run-time command output (debug)
  --auto               Auto-yes prompts (non-interactive)
  --help               Show this help

Examples:
  sudo /usr/local/bin/onionsite-orchestrator.sh --install
  sudo /usr/local/bin/onionsite-orchestrator.sh --self-heal
  sudo /usr/local/bin/onionsite-orchestrator.sh --rotate-keys --auto
EOF
}

# parse args
CMD=""
while (( "$#" )); do
  case "$1" in
    --install) CMD="install"; shift;;
    --deploy) CMD="deploy"; shift;;
    --status) CMD="status"; shift;;
    --show) CMD="show"; shift;;
    --backup) CMD="backup"; shift;;
    --rotate-keys) CMD="rotate"; shift;;
    --watchdog-enable) CMD="watchdog-enable"; shift;;
    --watchdog-disable) CMD="watchdog-disable"; shift;;
    --self-heal) CMD="self-heal"; shift;;
    --remove) CMD="remove"; shift;;
    --dry-run) DRY_RUN=true; shift;;
    --verbose) VERBOSE=true; shift;;
    --auto) AUTO_YES=true; shift;;
    --help) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 2;;
  esac
done

require_root

case "$CMD" in
  install)
    install_packages
    ensure_tor_default_instance || true
    prepare_webroot
    write_nginx_site
    ensure_hidden_service || warn "Hidden service may not have been created; check Tor logs."
    configure_firewall
    action_status
    ;;
  deploy)
    prepare_webroot
    write_nginx_site
    ensure_hidden_service || warn "Hidden service may not have been created; check Tor logs."
    action_status
    ;;
  status)
    action_status
    ;;
  show)
    if [ -f "$HSDIR/hostname" ]; then
      cat "$HSDIR/hostname"
    else
      echo "(no onion hostname found at $HSDIR/hostname)"
      exit 1
    fi
    ;;
  backup)
    action_backup
    ;;
  rotate)
    action_rotate_keys
    ;;
  watchdog-enable)
    install_watchdog
    ;;
  watchdog-disable)
    remove_watchdog
    ;;
  self-heal)
    self_heal
    ;;
  remove)
    confirm_or_abort "Destroy onion site, configs and hidden keys? This is irreversible. Continue"
    run "systemctl stop nginx || true"
    run "systemctl stop tor@default || true"
    run "systemctl stop tor || true"
    run "rm -rf '$WEB_ROOT' '$NGINX_SITE_CONF' '$NGINX_SITE_LINK' '$HSDIR' || true"
    run "systemctl restart nginx || true"
    log "Removal complete."
    ;;
  "")
    usage; exit 0
    ;;
  *)
    echo "Unknown command: $CMD"; usage; exit 2
    ;;
esac

exit 0

