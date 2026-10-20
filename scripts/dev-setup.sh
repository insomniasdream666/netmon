#!/usr/bin/env bash
# NetMon developer setup: install dependencies, verify tools and prepare config.
#
# Usage:
#   ./scripts/dev-setup.sh              # install into the current environment
#   ./scripts/dev-setup.sh --venv       # create and use ./.venv instead
#   ./scripts/dev-setup.sh --no-influx  # skip the docker compose InfluxDB start
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

USE_VENV=0
START_INFLUX=1
for arg in "$@"; do
  case "$arg" in
    --venv) USE_VENV=1 ;;
    --no-influx) START_INFLUX=0 ;;
    -h|--help)
      sed -n '2,8p' "$0"
      exit 0
      ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

info()  { printf '  %s\n' "$*"; }
warn()  { printf '  warning: %s\n' "$*" >&2; }
have()  { command -v "$1" >/dev/null 2>&1; }

echo "NetMon developer setup"
echo "======================"

# ---------------------------------------------------------------------------
# 1. Python
# ---------------------------------------------------------------------------
if [ "$USE_VENV" -eq 1 ]; then
  PYTHON_BIN="${PYTHON_BIN:-python3}"
  if [ ! -d .venv ]; then
    info "creating virtual environment in .venv"
    "$PYTHON_BIN" -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  info "using $(python -c 'import sys; print(sys.executable)')"
else
  info "using $(python3 -c 'import sys; print(sys.executable)')"
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
info "python $PY_VERSION"
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "error: Python 3.11 or newer is required" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Python dependencies
# ---------------------------------------------------------------------------
PIP_FLAGS=()
if python3 -c 'import sysconfig,sys; raise SystemExit(0 if sysconfig.get_paths()["purelib"].startswith("/usr/lib") else 1)' 2>/dev/null; then
  warn "installing into the system Python; adding --break-system-packages"
  PIP_FLAGS+=(--break-system-packages)
fi

info "installing netmon with dev extras"
python3 -m pip install --quiet "${PIP_FLAGS[@]}" -e ".[dev]"

# ---------------------------------------------------------------------------
# 3. System tools
# ---------------------------------------------------------------------------
echo
echo "System tools"
REQUIRED_TOOLS=(ip ss ping)
OPTIONAL_TOOLS=(nmap iw iwconfig traceroute tracepath openssl dig resolvectl journalctl nmcli ethtool)
MISSING_REQUIRED=()
for tool in "${REQUIRED_TOOLS[@]}"; do
  if have "$tool"; then
    info "$tool: ok"
  else
    MISSING_REQUIRED+=("$tool")
    warn "$tool: missing (required)"
  fi
done
for tool in "${OPTIONAL_TOOLS[@]}"; do
  if have "$tool"; then
    info "$tool: ok"
  else
    info "$tool: absent (optional features disabled)"
  fi
done

if [ "${#MISSING_REQUIRED[@]}" -gt 0 ]; then
  warn "install the missing required tools, e.g. sudo apt install -y ${MISSING_REQUIRED[*]}"
fi

if have nmap; then
  echo
  info "nmap SYN scans need root; NetMon falls back to TCP connect scans otherwise."
  info "optional sudoers entry for unprivileged SYN scans:"
  echo "      $(whoami) ALL=(root) NOPASSWD: /usr/bin/nmap"
fi

# ---------------------------------------------------------------------------
# 4. InfluxDB
# ---------------------------------------------------------------------------
if [ "$START_INFLUX" -eq 1 ]; then
  echo
  echo "InfluxDB"
  if have docker; then
    if [ -f docker/docker-compose.yml ]; then
      info "starting influxdb via docker compose"
      (cd docker && docker compose up -d influxdb) || warn "could not start influxdb"
      info "export INFLUX_TOKEN before running NetMon with metrics enabled"
    fi
  else
    info "docker not found; skipping InfluxDB (NetMon keeps metrics in memory)"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Configuration
# ---------------------------------------------------------------------------
echo
echo "Configuration"
CONFIG_DIR="$HOME/.config/netmon"
mkdir -p "$CONFIG_DIR"
if [ -f "$CONFIG_DIR/config.yaml" ]; then
  info "existing configuration kept at $CONFIG_DIR/config.yaml"
else
  info "writing default configuration to $CONFIG_DIR/config.yaml"
  python3 - <<'PY'
from netmon.config.settings import load_config, save_config
save_config(load_config())
PY
fi
if [ -f .env.example ] && [ ! -f .env ]; then
  cp .env.example .env
  info "created .env from .env.example"
fi

# ---------------------------------------------------------------------------
# 6. Verification
# ---------------------------------------------------------------------------
echo
echo "Verification"
python3 -c "import netmon; print('  netmon', netmon.__version__)"
python3 -m netmon doctor || true

cat <<'EOF'

Next steps
----------
  python -m netmon              # Textual TUI
  python -m netmon --web        # web dashboard on http://localhost:8080
  netmon diagnose               # one-shot AI/rule diagnosis
  ollama serve && ollama pull llama3:8b   # enable AI diagnostics
EOF
