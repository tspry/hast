#!/usr/bin/env bash
# HAST – Docker launcher
# Requires: docker with compose plugin (v2) or standalone docker-compose (v1)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "\033[0;34m[*]\033[0m $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
  ██╗  ██╗ █████╗ ███████╗████████╗
  ██║  ██║██╔══██╗██╔════╝╚══██╔══╝
  ███████║███████║███████╗   ██║
  ██╔══██║██╔══██║╚════██║   ██║
  ██║  ██║██║  ██║███████║   ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝
BANNER
echo -e "${NC}${BOLD}  Hardening & Attack Surface Tester${NC}"
echo ""

# ── Detect docker compose command ─────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  error "Docker not found. Install Docker Desktop or Docker Engine first."
fi

if docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  COMPOSE="docker-compose"
else
  error "Neither 'docker compose' (v2) nor 'docker-compose' (v1) found."
fi

success "Docker: $(docker --version | cut -d' ' -f3 | tr -d ',')"
success "Compose: $($COMPOSE version --short 2>/dev/null || $COMPOSE version)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT=8765
HOST="127.0.0.1"

# Parse optional flags
BUILD=false
DETACH=false
LOGS=false
DOWN=false

for arg in "$@"; do
  case "$arg" in
    --build|-b)  BUILD=true ;;
    --detach|-d) DETACH=true ;;
    --logs|-l)   LOGS=true ;;
    --down)      DOWN=true ;;
    --help|-h)
      echo ""
      echo "Usage: ./start.sh [options]"
      echo ""
      echo "  (no flags)   Build if needed, start in foreground"
      echo "  --build, -b  Force rebuild before starting"
      echo "  --detach, -d Run in background"
      echo "  --logs, -l   Attach to logs of a running container"
      echo "  --down       Stop and remove the container"
      echo ""
      exit 0
      ;;
  esac
done

# ── Stop ───────────────────────────────────────────────────────────────────────
if $DOWN; then
  info "Stopping HAST..."
  $COMPOSE down
  success "Stopped."
  exit 0
fi

# ── Logs ───────────────────────────────────────────────────────────────────────
if $LOGS; then
  $COMPOSE logs -f hast
  exit 0
fi

# ── Check if image needs building ─────────────────────────────────────────────
IMAGE_EXISTS=$(docker images -q hast-scanner:latest 2>/dev/null)

if $BUILD || [ -z "$IMAGE_EXISTS" ]; then
  info "Building image (this takes a few minutes the first time)..."
  $COMPOSE build
fi

# ── Start ─────────────────────────────────────────────────────────────────────
echo ""
info "Starting HAST container..."
info "Dashboard will be available at: ${CYAN}http://${HOST}:${PORT}${NC}"
echo ""

if $DETACH; then
  $COMPOSE up -d
  echo ""
  success "HAST running in background."
  info "View logs:  ./start.sh --logs"
  info "Stop:       ./start.sh --down"
  echo ""
  # Try to open browser
  URL="http://${HOST}:${PORT}"
  if command -v open &>/dev/null; then
    sleep 2 && open "$URL" &
  elif command -v xdg-open &>/dev/null; then
    sleep 2 && xdg-open "$URL" &
  fi
else
  # Foreground — open browser after a delay, then tail compose
  (
    sleep 4
    URL="http://${HOST}:${PORT}"
    if command -v open &>/dev/null; then open "$URL"
    elif command -v xdg-open &>/dev/null; then xdg-open "$URL"
    fi
  ) &
  echo -e "${CYAN}  Press Ctrl+C to stop${NC}"
  echo ""
  $COMPOSE up
fi
