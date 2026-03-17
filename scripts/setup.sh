#!/usr/bin/env bash
##
## IP Camera System — Initial Setup
##
## Run once before starting the system:
##   cd ip-camera-system && ./scripts/setup.sh
##
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BOLD='\033[1m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[setup]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[warn] ${RESET} $*"; }
error() { echo -e "${RED}[error]${RESET} $*"; exit 1; }

echo -e "${BOLD}IP Camera System — Setup${RESET}"
echo "─────────────────────────────────────────"

## ── Check prerequisites ───────────────────────────────────────────────────
info "Checking prerequisites…"

if ! command -v docker &>/dev/null; then
  error "Docker is not installed. See https://docs.docker.com/get-docker/"
fi

DOCKER_COMPOSE=""
if docker compose version &>/dev/null 2>&1; then
  DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  DOCKER_COMPOSE="docker-compose"
else
  error "Docker Compose not found. Install the Docker Compose plugin."
fi

info "Docker   : $(docker --version)"
info "Compose  : $($DOCKER_COMPOSE version --short 2>/dev/null || $DOCKER_COMPOSE version)"

## ── Create directories ────────────────────────────────────────────────────
info "Creating data directories…"
mkdir -p recordings hls config

## ── Copy .env if missing ──────────────────────────────────────────────────
if [[ ! -f ".env" ]]; then
  warn ".env not found — using defaults (check .env for customisation)"
fi

## ── Load .env ─────────────────────────────────────────────────────────────
if [[ -f ".env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' .env | grep -v '^$' | xargs)
fi

RECORDINGS_DIR="${RECORDINGS_DIR:-./recordings}"
HLS_DIR="${HLS_DIR:-./hls}"

info "Recordings dir : $RECORDINGS_DIR"
info "HLS dir        : $HLS_DIR"

## ── Create directories (resolved path) ────────────────────────────────────
mkdir -p "$RECORDINGS_DIR" "$HLS_DIR"

## ── Pull Nginx image early ────────────────────────────────────────────────
info "Pulling nginx image…"
docker pull nginx:1.25-alpine --quiet

## ── Build application images ──────────────────────────────────────────────
info "Building application images (this may take a few minutes)…"
$DOCKER_COMPOSE build

## ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Setup complete!${RESET}"
echo "─────────────────────────────────────────"
echo ""
echo " Next steps:"
echo ""
echo "  1. Edit  config/cameras.yml  — add your camera credentials, or"
echo "           let the ONVIF scanner discover cameras automatically."
echo ""
echo "  2. Start the system:"
echo "       $DOCKER_COMPOSE up -d"
echo ""
echo "  3. Open the dashboard:"
echo "       http://$(hostname -I | awk '{print $1}'):${HTTP_PORT:-80}"
echo ""
echo "  4. To follow live logs:"
echo "       $DOCKER_COMPOSE logs -f"
echo ""
