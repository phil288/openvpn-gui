"""Single-instance app with IPC to open .ovpn files in a running window."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from PySide6.QtNetwork import QLocalServer, QLocalSocket

from openvpn_manager.widgets.ovpn_drop import OVPN_SUFFIX

_SERVER_BASE = "openvpn-manager"


def _server_name() -> str:
    return f"{_SERVER_BASE}-{os.getuid()}"


def ovpn_paths_from_argv(argv: list[str] | None = None) -> list[Path]:
    """Collect .ovpn file paths from command-line arguments."""
    argv = argv if argv is not None else sys.argv
    paths: list[Path] = []
    seen: set[Path] = set()
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        path = Path(arg).expanduser()
        if path.suffix.lower() != OVPN_SUFFIX:
            continue
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved.is_file() and resolved not in seen:
            seen.add(resolved)
            paths.append(resolved)
    return paths


def is_instance_running() -> bool:
    """Return True if another OpenVPN Manager process is listening."""
    socket = QLocalSocket()
    socket.connectToServer(_server_name())
    if socket.waitForConnected(500):
        socket.disconnectFromServer()
        return True
    return False


def try_forward_files(paths: list[Path]) -> bool:
    """Send file paths to a running instance, or raise its window. Returns True if handled."""
    socket = QLocalSocket()
    socket.connectToServer(_server_name())
    if not socket.waitForConnected(1000):
        return False
    payload = json.dumps([str(p) for p in paths]).encode("utf-8")
    socket.write(payload)
    socket.waitForBytesWritten(2000)
    socket.disconnectFromServer()
    return True


_PGREP_PATTERNS = (
    "openvpn-manager",
    "openvpn_manager.app",
    "openvpn_manager/app",
    "openvpn_manager.app:main",
)


def find_manager_pids() -> list[int]:
    """Return PIDs of OpenVPN Manager processes for the current user."""
    uid = os.getuid()
    found: set[int] = set()
    for pattern in _PGREP_PATTERNS:
        result = subprocess.run(
            ["pgrep", "-u", str(uid), "-f", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                found.add(int(line))
    return sorted(found)


def kill_all_manager_processes() -> int:
    """Force-stop every OpenVPN Manager process for this user. Returns count killed."""
    my_pid = os.getpid()
    pids = [p for p in find_manager_pids() if p != my_pid]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    if pids:
        time.sleep(0.4)
    killed = 0
    for pid in pids:
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
            killed += 1
        except OSError:
            pass
    try:
        QLocalServer.removeServer(_server_name())
    except Exception:
        pass
    return killed


class SingleInstanceServer:
    """Listen for .ovpn paths from secondary process launches."""

    def __init__(self, on_files) -> None:
        self._on_files = on_files
        self._server = QLocalServer()
        self._server.newConnection.connect(self._on_new_connection)
        QLocalServer.removeServer(_server_name())
        if not self._server.listen(_server_name()):
            raise RuntimeError(
                f"Could not start single-instance server: {self._server.errorString()}"
            )

    def close(self) -> None:
        if self._server.isListening():
            self._server.close()
        QLocalServer.removeServer(_server_name())

    def _on_new_connection(self) -> None:
        socket = self._server.nextPendingConnection()
        if not socket:
            return
        if socket.waitForReadyRead(3000):
            data = socket.readAll().data().decode("utf-8")
            try:
                raw = json.loads(data)
                if not isinstance(raw, list):
                    return
                paths = [
                    Path(p)
                    for p in raw
                    if isinstance(p, str)
                    and Path(p).suffix.lower() == OVPN_SUFFIX
                    and Path(p).is_file()
                ]
                self._on_files(paths)
            except (json.JSONDecodeError, TypeError):
                pass
        socket.disconnectFromServer()
