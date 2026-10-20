#!/usr/bin/env bash
# NetMon production installer for Kali Linux / Debian.
#
# Usage:
#   sudo ./scripts/install.sh                 # system-wide install + systemd service
#   ./scripts/install.sh --user               # per-user install, user service
#   ./scripts/install.sh --no-service         # install only, do not touch systemd
#
# What it does:
#   1. verifies the platform and required tools
#   2. installs NetMon into a dedicated virtual environment
#   3. installs the systemd unit (user or system scope) and logrotate policy
#   4. writes a default configuration if none exists
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_ROOT="/opt/netmon"
VENV_DIR="${INSTALL_ROOT}/venv"
SCOPE="system"
INSTALL_SERVICE=1
RUN_USER="${SUDO_USER:-${USER}}"

for arg in "$@"; do
  case "$arg" in
    --user) SCOPE="user" ;;
    --system) SCOPE="system" ;;
    --no-service) INSTALL_SERVICE=0 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

info() { printf '  %s\n' "$*"; }
warn() { printf '  warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || [ "$SCOPE" = "user" ] || die "run with sudo for a system install, or pass --user"
[ -f "${PROJECT_ROOT}/pyproject.toml" ] || die "run this script from the NetMon repository"

echo "NetMon installer"
echo "================"
info "project: ${PROJECT_ROOT}"
info "scope:   ${SCOPE}"

# ---------------------------------------------------------------------------
# 1. Platform and dependencies
# ---------------------------------------------------------------------------
echo
echo "System prerequisites"
command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "Python 3.11 or newer is required (found $(python3 -V))"
info "python: $(python3 -V)"

REQUIRED_PACKAGES=(nmap iproute2 iputils-ping procps openssl)
OPTIONAL_PACKAGES=(iw wireless-tools traceroute dnsutils ethtool)
if command -v apt-get >/dev/null; then
  MISSING=()
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    dpkg -s "$pkg" >/dev/null 2>&1 || MISSING+=("$pkg")
  done
  if [ "${#MISSING[@]}" -gt 0 ]; then
    info "installing required packages: ${MISSING[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING[@]}"
  else
    info "required packages present"
  fi
  if [ "$SCOPE" = "system" ]; then
    OPTIONAL_MISSING=()
    for pkg in "${OPTIONAL_PACKAGES[@]}"; do
      dpkg -s "$pkg" >/dev/null 2>&1 || OPTIONAL_MISSING+=("$pkg")
    done
    if [ "${#OPTIONAL_MISSING[@]}" -gt 0 ]; then
      info "optional packages not installed: ${OPTIONAL_MISSING[*]}"
      info "install them with: apt-get install -y ${OPTIONAL_MISSING[*]}"
    fi
  fi
else
  warn "apt-get not found; ensure nmap, iproute2, iputils-ping and openssl are installed"
fi

# ---------------------------------------------------------------------------
# 2. Install into a virtual environment
# ---------------------------------------------------------------------------
echo
echo "Application install"
if [ "$SCOPE" = "system" ]; then
  mkdir -p "$INSTALL_ROOT"
  if [ ! -d "$VENV_DIR" ]; then
    info "creating virtual environment at ${VENV_DIR}"
    python3 -m venv "$VENV_DIR"
  fi
  info "installing netmon (this may take a minute)"
  "$VENV_DIR/bin/pip" install --quiet --upgrade pip
  "$VENV_DIR/bin/pip" install --quiet "$PROJECT_ROOT"
  chmod -R a+rX "$INSTALL_ROOT"
  BIN_PATH="${VENV_DIR}/bin/netmon"
else
  VENV_DIR="${HOME}/.local/share/netmon/venv"
  if [ ! -d "$VENV_DIR" ]; then
    info "creating virtual environment at ${VENV_DIR}"
    python3 -m venv "$VENV_DIR"
  fi
  "$VENV_DIR/bin/pip" install --quiet --upgrade pip
  "$VENV_DIR/bin/pip" install --quiet "$PROJECT_ROOT"
  BIN_PATH="${VENV_DIR}/bin/netmon"
  mkdir -p "${HOME}/.local/bin"
  ln -sf "$BIN_PATH" "${HOME}/.local/bin/netmon"
  info "linked ${HOME}/.local/bin/netmon"
fi
info "binary: ${BIN_PATH}"

# ---------------------------------------------------------------------------
# 3. Configuration
# ---------------------------------------------------------------------------
echo
echo "Configuration"
CONFIG_DIR="$([ "$SCOPE" = "system" ] && echo "${INSTALL_ROOT}/config" || echo "${HOME}/.config/netmon")"
mkdir -p "$CONFIG_DIR"
if [ -f "${CONFIG_DIR}/config.yaml" ]; then
  info "existing configuration kept: ${CONFIG_DIR}/config.yaml"
else
  info "writing default configuration: ${CONFIG_DIR}/config.yaml"
  cat > "${CONFIG_DIR}/config.yaml" <<'YAML'
# NetMon configuration - see docs/usage.md for the full reference.
monitoring:
  intervals: {interfaces: 2, connectivity: 10, bandwidth: 5, ports: 300, connections: 15, wifi: 30, certificates: 3600}
  targets:
    ping: [8.8.8.8, 1.1.1.1, 9.9.9.9]
    dns: [google.com, github.com, cloudflare.com]
    traceroute: [8.8.8.8]
    certificates: ["github.com:443", "google.com:443"]
  ignored_interfaces: [lo, "docker*", "veth*", "br-*", "virbr*", "tun*"]
health:
  thresholds:
    latency_warning: 50
    latency_critical: 200
    packet_loss_warning: 1
    packet_loss_critical: 5
    bandwidth_util_warning: 80
    bandwidth_util_critical: 95
    dns_latency_warning: 100
    cert_expiry_warning_days: 30
    cert_expiry_critical_days: 7
alerts:
  enabled: true
  cooldown: 300
  channels:
    - {type: log}
ollama:
  enabled: true
  host: http://localhost:11434
  model: llama3:8b
  timeout: 30
storage:
  sqlite_path: ~/.config/netmon/config.db
  influxdb:
    url: http://localhost:8086
    org: netmon
    bucket: metrics
web:
  host: 0.0.0.0
  port: 8080
YAML
  chmod 600 "${CONFIG_DIR}/config.yaml"
fi
if [ "$SCOPE" = "system" ]; then
  chown -R "${RUN_USER}:${RUN_USER}" "$CONFIG_DIR" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 4. systemd service
# ---------------------------------------------------------------------------
if [ "$INSTALL_SERVICE" -eq 1 ]; then
  echo
  echo "systemd"
  if [ "$SCOPE" = "system" ]; then
    UNIT_PATH="/etc/systemd/system/netmon.service"
    info "writing ${UNIT_PATH}"
    cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=NetMon - See your network. Fix it fast.
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
ExecStart=${BIN_PATH} --headless
WorkingDirectory=${INSTALL_ROOT}
Environment=NETMON_ENV=production
Environment=NETMON_CONFIG_PATH=${CONFIG_DIR}/config.yaml
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=5
Nice=5
NoNewPrivileges=true
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now netmon.service
    info "service enabled and started"
    info "logs: journalctl -u netmon -f"
  else
    UNIT_DIR="${HOME}/.config/systemd/user"
    mkdir -p "$UNIT_DIR"
    info "writing ${UNIT_DIR}/netmon.service"
    cat > "${UNIT_DIR}/netmon.service" <<UNIT
[Unit]
Description=NetMon - See your network. Fix it fast.
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} --headless
Environment=NETMON_ENV=production
Environment=NETMON_CONFIG_PATH=${CONFIG_DIR}/config.yaml
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=5
Nice=5
NoNewPrivileges=true

[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable --now netmon.service
    info "user service enabled and started"
    info "logs: journalctl --user -u netmon -f"
  fi

  # logrotate for headless deployments that redirect output to a file
  if [ "$SCOPE" = "system" ] && [ -d /etc/logrotate.d ]; then
    cat > /etc/logrotate.d/netmon <<'LOGROTATE'
/var/log/netmon/netmon.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
LOGROTATE
    info "logrotate policy installed at /etc/logrotate.d/netmon"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Optional: InfluxDB and Ollama hints
# ---------------------------------------------------------------------------
cat <<'EOF'

Optional services
-----------------
InfluxDB (time-series metrics):
  export INFLUXDB_PASSWORD="$(openssl rand -hex 16)"
  export INFLUX_TOKEN="$(openssl rand -hex 24)"
  docker run -d --name influxdb -p 8086:8086 \
    -e DOCKER_INFLUXDB_INIT_MODE=setup -e DOCKER_INFLUXDB_INIT_USERNAME=admin \
    -e DOCKER_INFLUXDB_INIT_PASSWORD="$INFLUXDB_PASSWORD" -e DOCKER_INFLUXDB_INIT_ORG=netmon \
    -e DOCKER_INFLUXDB_INIT_BUCKET=metrics -e DOCKER_INFLUXDB_INIT_ADMIN_TOKEN="$INFLUX_TOKEN" influxdb:2.7
  export INFLUXDB_TOKEN="$INFLUX_TOKEN"   # add to the unit file Environment= lines

Ollama (AI diagnostics):
  ollama serve && ollama pull llama3:8b

Verify
------
  netmon doctor
  netmon status
EOF

echo
info "install complete"
