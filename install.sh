#!/usr/bin/env bash
# Install OpenVPN Manager on Fedora (or other Linux with dnf/python3).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/.venv}"
INSTALL_DESKTOP="${INSTALL_DESKTOP:-1}"
INSTALL_POLKIT="${INSTALL_POLKIT:-0}"
INSTALL_SYSTEM_DEPS="${INSTALL_SYSTEM_DEPS:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}warning:${NC} $*" >&2; }
die()   { echo -e "${RED}error:${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Install OpenVPN Manager into a local Python virtualenv and desktop launcher.

Options:
  --system-deps     Install openvpn and python3-devel via dnf (Fedora)
  --polkit          Install legacy PolicyKit policy (not required; app uses sudo cache)
  --no-desktop      Skip ~/.local/share/applications launcher
  --venv PATH       Virtualenv directory (default: $SCRIPT_DIR/.venv)
  -h, --help        Show this help

Examples:
  ./install.sh
  ./install.sh --system-deps
  sudo ./install.sh --no-desktop   # not recommended; use normal user
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --system-deps)
            INSTALL_SYSTEM_DEPS=1
            shift
            ;;
        --polkit)
            INSTALL_POLKIT=1
            shift
            ;;
        --no-desktop)
            INSTALL_DESKTOP=0
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
            die "Unknown option: $1 (try --help)"
            ;;
    esac
done

# --- system dependencies (optional) ---
if [[ "$INSTALL_SYSTEM_DEPS" == "1" ]]; then
    if command -v dnf &>/dev/null; then
        info "Installing system packages (openvpn, python3, pip, venv)…"
        sudo dnf install -y openvpn python3 python3-pip python3-virtualenv
    else
        warn "--system-deps requires dnf (Fedora/RHEL). Install openvpn and python3 manually."
    fi
fi

# --- openvpn ---
OPENVPN_BIN=""
if command -v openvpn &>/dev/null; then
    OPENVPN_BIN="$(command -v openvpn)"
else
    warn "openvpn not found in PATH."
    if command -v dnf &>/dev/null; then
        read -r -p "Install openvpn with dnf now? [y/N] " reply
        if [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]; then
            sudo dnf install -y openvpn
            OPENVPN_BIN="$(command -v openvpn)"
        fi
    fi
fi
[[ -n "$OPENVPN_BIN" ]] || die "openvpn is required. On Fedora: sudo dnf install openvpn"

# --- python ---
PYTHON=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        major="${ver%%.*}"
        minor="${ver#*.}"
        if [[ "$major" -eq 3 && "$minor" -ge 11 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done
[[ -n "$PYTHON" ]] || die "Python 3.11+ is required."

info "Using Python: $PYTHON ($($PYTHON --version))"

# --- virtualenv + package ---
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtualenv at $VENV_DIR"
    "$PYTHON" -m venv "$VENV_DIR"
fi

info "Installing OpenVPN Manager (editable)…"
"$VENV_DIR/bin/pip" install --upgrade pip wheel
"$VENV_DIR/bin/pip" install -e "$SCRIPT_DIR"

# --- PolicyKit (legacy, optional) ---
if [[ "$INSTALL_POLKIT" == "1" ]]; then
    POLKIT_DST="/usr/share/polkit-1/actions/com.openvpnmanager.policy"
    POLKIT_TMP="$(mktemp)"
    sed "s|/usr/bin/openvpn|${OPENVPN_BIN}|g" \
        "$SCRIPT_DIR/packaging/com.openvpnmanager.policy" > "$POLKIT_TMP"
    info "Installing legacy PolicyKit action (sudo) → $POLKIT_DST"
    sudo install -m 0644 "$POLKIT_TMP" "$POLKIT_DST"
    rm -f "$POLKIT_TMP"
fi

# --- MIME type + desktop launcher ---
if [[ "$INSTALL_DESKTOP" == "1" ]]; then
    APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    MIME_PKG_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/mime/packages"
    ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
    mkdir -p "$APPS_DIR" "$MIME_PKG_DIR" "$ICON_DIR"

    MIME_SRC="$SCRIPT_DIR/packaging/openvpn-manager-mime.xml"
    if [[ -f "$MIME_SRC" ]]; then
        info "Installing MIME type for .ovpn → $MIME_PKG_DIR"
        cp -f "$MIME_SRC" "$MIME_PKG_DIR/openvpn-manager.xml"
        if command -v update-mime-database &>/dev/null; then
            update-mime-database "${XDG_DATA_HOME:-$HOME/.local/share}/mime" 2>/dev/null || true
        fi
    fi

    ICON_SRC="$SCRIPT_DIR/openvpn_manager/resources/icons/app.svg"
    ICON_DST="$ICON_DIR/openvpn-manager.svg"
    if [[ -f "$ICON_SRC" ]]; then
        cp -f "$ICON_SRC" "$ICON_DST"
    fi

    DESKTOP_FILE="$APPS_DIR/openvpn-manager.desktop"
    EXEC_LINE="$VENV_DIR/bin/openvpn-manager"
    info "Writing desktop entry → $DESKTOP_FILE"

    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=OpenVPN Manager
Comment=Manage OpenVPN connections
Exec=${EXEC_LINE} %F
Icon=openvpn-manager
Categories=Network;Security;
MimeType=application/x-openvpn-profile;
StartupNotify=true
Terminal=false
EOF

    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database "$APPS_DIR" 2>/dev/null || true
    fi

    if command -v xdg-mime &>/dev/null; then
        info "Setting OpenVPN Manager as default app for .ovpn files"
        xdg-mime default openvpn-manager.desktop application/x-openvpn-profile 2>/dev/null || \
            warn "Could not set default handler (set manually: Open With → OpenVPN Manager)"
    fi
fi

# --- done ---
echo ""
info "Installation complete."
echo ""
echo "  Run from terminal:"
echo "    $VENV_DIR/bin/openvpn-manager"
echo ""
if [[ "$INSTALL_DESKTOP" == "1" ]]; then
    echo "  Or launch “OpenVPN Manager” from your application menu."
    echo ""
fi
echo "  Uninstall desktop entry: rm ~/.local/share/applications/openvpn-manager.desktop"
echo "  VPN connects use sudo; your login password authorizes the session sudo"
echo "  timestamp and is never stored. For passwordless connects: ./install.sh --polkit"
