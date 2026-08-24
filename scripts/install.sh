#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-$PROJECT_ROOT/.venv}"

log() {
  echo "[ulpf] $*"
}

if ! "$PYTHON_BIN" --version >/dev/null 2>&1; then
  echo "[ulpf] Python 3 is required but not found in PATH." >&2
  exit 1
fi

log "Installing Universal Log Pre-processing Framework"
log "Project root: $PROJECT_ROOT"

mkdir -p "$PROJECT_ROOT/logs" "$PROJECT_ROOT/data" "$PROJECT_ROOT/config"

if [ ! -d "$VENV_DIR" ]; then
  log "Creating virtual environment at $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip setuptools wheel
python -m pip install -r "$PROJECT_ROOT/requirements.txt"
python -m pip install -e "$PROJECT_ROOT"

if [ ! -f "$PROJECT_ROOT/.env" ]; then
  cat > "$PROJECT_ROOT/.env" <<EOF
# ULPF runtime settings
LOG_INPUT_PATH=./logs
LOG_OUTPUT_PATH=./data
LOG_FORMATS=syslog,json,cef,xml,csv
ENABLE_RAW_RETENTION=true
BUFFER_SIZE_MB=256
EOF
fi

if command -v docker >/dev/null 2>&1; then
  log "Validating Docker Compose configuration"
  (cd "$PROJECT_ROOT/infra" && docker compose config >/dev/null)
else
  log "Docker not found in PATH; skipping container validation."
fi

log "Installation complete."
log "Activate the environment with: source $VENV_DIR/bin/activate"
log "Run the CLI with: ulpf --help"
log "To start the log pipeline: cd $PROJECT_ROOT/infra && docker compose up --build"
