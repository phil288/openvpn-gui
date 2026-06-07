# OpenVPN Manager

Desktop GUI for managing OpenVPN connections on Fedora and Ubuntu — similar to OpenVPN Connect on Windows.

## Features

- Import `.ovpn` profiles (file picker or drag-and-drop)
- One-click connect / disconnect
- Real-time stats (VPN IP, bytes in/out, duration)
- VPN and login passwords stored in the **system keyring** (GNOME Keyring / KWallet)
- **Sudo credential cache** — asked once, then reused (sudo timestamp + optional keyring)
- System tray with quick connect menu
- No PolicyKit popup on every connect

## Requirements

- Fedora, Ubuntu, or another Linux with `sudo` and Python 3.11+
- `openvpn`:
  - Fedora: `sudo dnf install openvpn`
  - Ubuntu: `sudo apt install openvpn`

## Install

```bash
cd openvpn-connect
./install.sh
```

`./install.sh` creates a local virtualenv and a desktop launcher. It needs
`openvpn` and Python 3.11+ already present.

**Fedora** — install the system dependencies automatically:

```bash
./install.sh --system-deps   # uses dnf
```

**Ubuntu** — install the system dependencies first, then run the installer:

```bash
sudo apt update
sudo apt install openvpn python3 python3-venv python3-pip
./install.sh
```

> `--system-deps` only supports `dnf` (Fedora/RHEL). On Ubuntu install the
> packages with `apt` as shown above; the installer detects the existing
> `openvpn` and Python.

## Run

```bash
source .venv/bin/activate
pip install -e .   # re-run after pulling updates
openvpn-manager
```

## Usage

1. **Double-click** a `.ovpn` file, **drag and drop** onto the window, or use **Import…**.
2. Click **Connect**. The first time elevation is needed, enter your **login password** and check **Remember** to store it in the keyring.
3. Later connects reuse the **sudo cache** (typically several minutes) and the saved password when the cache expires.
4. VPN usernames/passwords (`auth-user-pass`) are separate — use **Credentials…** per profile.
5. Close the window to keep running in the tray; use **Exit application** from the tray menu to quit.

## How elevation works

| Case | Behaviour |
|------|-----------|
| Running as root | OpenVPN runs directly |
| Normal user | `sudo -n openvpn …` after a cached sudo ticket (TUN needs root) |
| First connect / expired cache | Login password dialog; optional keyring storage |
| App startup | Restores sudo cache from keyring if saved |

## Tests

```bash
./scripts/run-tests.sh
# or
.venv/bin/pytest tests/unit -v
```

## Profile storage

- Configs: `~/.config/openvpn-manager/profiles/*.ovpn`
- Index: `~/.config/openvpn-manager/profiles.json`

## Troubleshooting

- **Authentication failed**: Wrong login password for sudo.
- **OpenVPN exited immediately / management socket**: Sudo cache expired — connect again (keyring password is applied automatically if saved).
- **Management socket error**: Read the log panel; check `openvpn` is installed and the profile is valid.
- **Cannot allocate DCO dev**: The app forces `--disable-dco` (classic TUN). Update the app if you still see this on an old build.
- **No tray icon**: Some desktops need a tray extension; the main window still works.

## License

MIT
