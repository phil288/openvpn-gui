#!/usr/bin/env bash
# Uninstall OpenVPN Manager.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/.venv}"
REMOVE_POLKIT="${REMOVE_POLKIT:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}warning:${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Uninstall OpenVPN Manager (virtualenv, desktop entry, MIME type, icon).

Options:
  --polkit          Also remove the legacy PolicyKit policy (requires sudo)
  --venv PATH       Virtualenv directory to remove (default: $SCRIPT_DIR/.venv)
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --polkit)
            REMOVE_POLKIT=1
            shift
            ;;
        --venv)
            VENV_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}error:${NC} Unknown option: $1 (try --help)" >&2
            exit 1
            ;;
    esac
done

# --- virtualenv ---
if [[ -d "$VENV_DIR" ]]; then
    info "Removing virtualenv at $VENV_DIR"
    rm -rf "$VENV_DIR"
else
    warn "Virtualenv not found at $VENV_DIR — skipping"
fi

# --- desktop entry ---
APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DESKTOP_FILE="$APPS_DIR/openvpn-manager.desktop"
if [[ -f "$DESKTOP_FILE" ]]; then
    info "Removing desktop entry → $DESKTOP_FILE"
    rm -f "$DESKTOP_FILE"
    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database "$APPS_DIR" 2>/dev/null || true
    fi
else
    warn "Desktop entry not found — skipping"
fi

# --- MIME type ---
MIME_PKG_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/mime/packages"
MIME_FILE="$MIME_PKG_DIR/openvpn-manager.xml"
if [[ -f "$MIME_FILE" ]]; then
    info "Removing MIME type package → $MIME_FILE"
    rm -f "$MIME_FILE"
    if command -v update-mime-database &>/dev/null; then
        update-mime-database "${XDG_DATA_HOME:-$HOME/.local/share}/mime" 2>/dev/null || true
    fi
else
    warn "MIME type package not found — skipping"
fi

# --- icon ---
ICON_FILE="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps/openvpn-manager.svg"
if [[ -f "$ICON_FILE" ]]; then
    info "Removing icon → $ICON_FILE"
    rm -f "$ICON_FILE"
else
    warn "Icon not found — skipping"
fi

# --- PolicyKit (legacy, optional) ---
if [[ "$REMOVE_POLKIT" == "1" ]]; then
    POLKIT_DST="/usr/share/polkit-1/actions/com.openvpnmanager.policy"
    if [[ -f "$POLKIT_DST" ]]; then
        info "Removing legacy PolicyKit action (sudo) → $POLKIT_DST"
        sudo rm -f "$POLKIT_DST"
    else
        warn "PolicyKit action not found — skipping"
    fi
fi

# --- done ---
echo ""
info "Uninstall complete."
