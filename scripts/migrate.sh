#!/usr/bin/env bash
##
## IP Camera System — Migration Helper
##
## Creates a portable archive of the entire system that can be unpacked
## on a different server and started with `docker compose up -d`.
##
## Usage:
##   ./scripts/migrate.sh [--exclude-recordings] [--dest user@host:/path]
##
## Options:
##   --exclude-recordings   Skip the large recordings directory
##                          (camera history will not be transferred)
##   --dest user@host:/path SCP the archive to a remote server after creation
##
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BOLD='\033[1m'
GREEN='\033[32m'
YELLOW='\033[33m'
RESET='\033[0m'

info() { echo -e "${GREEN}[migrate]${RESET} $*"; }
warn() { echo -e "${YELLOW}[warn]   ${RESET} $*"; }

EXCLUDE_RECORDINGS=false
DEST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exclude-recordings) EXCLUDE_RECORDINGS=true ;;
    --dest) DEST="$2"; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

# Load .env for RECORDINGS_DIR / HLS_DIR
if [[ -f ".env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' .env | grep -v '^$' | xargs) 2>/dev/null || true
fi

RECORDINGS_DIR="${RECORDINGS_DIR:-./recordings}"
HLS_DIR="${HLS_DIR:-./hls}"
ARCHIVE="ipcam-migration-$(date +%Y%m%d-%H%M%S).tar.gz"

echo -e "${BOLD}IP Camera System — Migration${RESET}"
echo "─────────────────────────────────────────"

## ── Stop services ─────────────────────────────────────────────────────────
DOCKER_COMPOSE=""
if docker compose version &>/dev/null 2>&1; then
  DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  DOCKER_COMPOSE="docker-compose"
fi

if [[ -n "$DOCKER_COMPOSE" ]]; then
  info "Stopping services…"
  $DOCKER_COMPOSE down --timeout 30 || true
fi

## ── Build tar exclude list ────────────────────────────────────────────────
EXCLUDES=(
  ".git"
  "*.pyc"
  "__pycache__"
  ".DS_Store"
  "*.tmp"
  # Exclude transient HLS segments (they regenerate on start)
  "${HLS_DIR#./}/*.ts"
)

if $EXCLUDE_RECORDINGS; then
  warn "Excluding recordings directory (camera history will NOT be transferred)"
  EXCLUDES+=("${RECORDINGS_DIR#./}")
fi

EXCLUDE_ARGS=()
for ex in "${EXCLUDES[@]}"; do
  EXCLUDE_ARGS+=(--exclude="$ex")
done

## ── Create archive ────────────────────────────────────────────────────────
info "Creating archive: $ARCHIVE"
TAR_ITEMS=(
  docker-compose.yml
  nginx/
  recorder/
  scanner/
  dashboard/
  scripts/
  config/
)
[[ -f ".env" ]] && TAR_ITEMS+=(".env")
[[ -d "$RECORDINGS_DIR" ]] && ! $EXCLUDE_RECORDINGS && TAR_ITEMS+=("$RECORDINGS_DIR")

tar -czf "$ARCHIVE" "${EXCLUDE_ARGS[@]}" "${TAR_ITEMS[@]}" 2>/dev/null || true

ARCHIVE_SIZE=$(du -sh "$ARCHIVE" 2>/dev/null | cut -f1)
info "Archive created: $ARCHIVE ($ARCHIVE_SIZE)"

## ── Optional SCP transfer ─────────────────────────────────────────────────
if [[ -n "$DEST" ]]; then
  info "Transferring to $DEST …"
  scp "$ARCHIVE" "$DEST/"
  info "Transfer complete"

  echo ""
  echo -e "${BOLD}On the destination server run:${RESET}"
  echo "  tar -xzf $ARCHIVE"
  echo "  cd ip-camera-system"          # adjust if your dir name differs
  echo "  ./scripts/setup.sh"
  echo "  docker compose up -d"
else
  echo ""
  echo -e "${BOLD}Migration archive ready: $ARCHIVE${RESET}"
  echo "─────────────────────────────────────────"
  echo ""
  echo " To restore on the new server:"
  echo ""
  echo "  1. Copy the archive:"
  echo "       scp $ARCHIVE user@new-server:/opt/"
  echo ""
  echo "  2. On the new server:"
  echo "       cd /opt"
  echo "       tar -xzf $ARCHIVE"
  echo "       cd ip-camera-system"
  echo "       ./scripts/setup.sh"
  echo "       docker compose up -d"
  echo ""
  echo " Notes:"
  echo "  • Make sure the new server can reach 192.168.100.0/24"
  echo "  • Update RECORDINGS_DIR in .env if you're using a different drive"
  echo "  • Camera RTSP credentials are stored in config/cameras.yml"
  echo ""
fi

## ── Optionally restart ────────────────────────────────────────────────────
if [[ -n "$DOCKER_COMPOSE" ]]; then
  read -rp "Restart services on this server now? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    $DOCKER_COMPOSE up -d
    info "Services restarted"
  fi
fi
