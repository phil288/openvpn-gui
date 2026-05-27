# OpenVPN Manager

Desktop GUI for managing OpenVPN connections on Fedora — similar to OpenVPN Connect on Windows.

## Features

- Import `.ovpn` profiles (file picker or drag-and-drop)
- One-click connect / disconnect
- Real-time stats (VPN IP, bytes in/out, duration)
- Credentials stored in system keyring (GNOME Keyring / KWallet)
- System tray with quick connect menu
- PolicyKit (`pkexec`) for privileged `openvpn` without a terminal

## Requirements

- Fedora (or Linux with PolicyKit)
- Python 3.11+
- `openvpn` package: `sudo dnf install openvpn`
- `polkit` (usually preinstalled)

## Install

```bash
cd /home/phil/dev/openvpn
./install.sh

# First-time on a clean system (installs openvpn + python via dnf):
./install.sh --system-deps
```

The script creates a virtualenv, installs the app, registers the PolicyKit rule for `pkexec`, registers `.ovpn` as `application/x-openvpn-profile`, sets OpenVPN Manager as the default handler, and adds a desktop launcher under `~/.local/share/applications/`.

After installing, double-clicking a `.ovpn` file opens OpenVPN Manager and imports the profile. Re-run `./install.sh` if you already installed before this was added.

## Run

```bash
source .venv/bin/activate
openvpn-manager
# or
python main.py
```

## Usage

1. **Double-click** a `.ovpn` file, **drag and drop** onto the window, or use **Import…**.
2. Select a profile and click **Connect** — enter your password when PolicyKit prompts.
3. If the profile uses `auth-user-pass`, set credentials via **Credentials…** (saved in keyring if you choose Remember).
4. Close the window to keep running in the system tray; double-click the tray icon to reopen.

## Profile storage

- Configs: `~/.config/openvpn-manager/profiles/*.ovpn`
- Index: `~/.config/openvpn-manager/profiles.json`

## Troubleshooting

- **pkexec fails**: Re-run `./install.sh` to install the PolicyKit policy. Approve the dialog when connecting.
- **Management socket error**: Usually means OpenVPN did not start; read the log panel for openvpn errors. Ensure `openvpn` is installed (`dnf install openvpn`).
- **No tray icon**: Some desktops require a tray extension; the app still works from the window.
- **Connection timeout**: Check firewall, server reachability, and that credentials are correct.

## License

MIT
