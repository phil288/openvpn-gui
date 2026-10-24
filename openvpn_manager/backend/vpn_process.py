"""VPN subprocess control: OpenVPN via its management interface, WireGuard via wg-quick."""

from __future__ import annotations

import getpass
import signal
from os import close as os_close
from os import environ as os_environ
from os import fspath as os_fspath
from os import getpid as os_getpid
from os import getuid as os_getuid
from os import kill as os_kill
import threading
from collections.abc import Callable
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot

from openvpn_manager.backend.privilege import (
    needs_elevation,
    openvpn_binary,
    sudo_ticket_valid,
    wg_quick_binary,
    wrap_openvpn_command,
    wrap_root_command,
)
from openvpn_manager.backend.wireguard_config import (
    build_runtime_config,
    first_address,
)

MANAGEMENT_HOST = "127.0.0.1"
POLL_INTERVAL_SEC = 2.0
CONNECT_TIMEOUT_SEC = 120.0
HANDSHAKE_STALL_SEC = 10.0
WG_QUICK_TIMEOUT_SEC = 60.0
# Warn when a WireGuard tunnel has received nothing this long after coming up:
# WireGuard has no connect handshake to fail, so a wrong key or unreachable
# endpoint otherwise looks "connected" forever.
WG_NO_RX_WARN_SEC = 15.0
SYS_CLASS_NET = Path("/sys/class/net")
WG_CONFIG_DIR = Path("/etc/wireguard")

# Server-pushed options that send *all* traffic into the tunnel. Filtered out
# unless the profile opts into full tunnelling, so a server that pushes a
# default route (but doesn't NAT/forward it) can't cut the host off the
# internet. pull-filter matches by prefix, so each entry covers its variants.
FULL_TUNNEL_PUSH_OPTIONS = (
    "redirect-gateway",
    "block-ipv6",
    "route 0.0.0.0 0.0.0.0",
    "route 0.0.0.0 128.0.0.0",
    "route 128.0.0.0 128.0.0.0",
    "route-ipv6 ::/0",
    "route-ipv6 ::/1",
    "route-ipv6 8000::/1",
    "route-ipv6 2000::/3",
)


def _runtime_dir() -> Path:
    override = os_environ.get("OPENVPN_MANAGER_RUNTIME_DIR")
    if override:
        path = Path(override)
    else:
        base = os_environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os_getuid()}"
        path = Path(base) / "openvpn-manager"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _resolve_ipv4(host: str) -> str | None:
    """Return an IPv4 (A-record) address for host, or None if it has none."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except (socket.gaierror, OSError):
        return None
    for info in infos:
        addr = info[4][0]
        if addr:
            return addr
    return None


def _ipv4_route_available(ipv4: str) -> bool:
    """True if the host has a native IPv4 route able to reach ``ipv4``.

    Uses a UDP "connect" which sends no packets but fails fast with
    ENETUNREACH when there is no usable IPv4 path (e.g. an IPv6-only /
    NAT64 network), letting us leave such setups on their working path.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        sock.connect((ipv4, 9))  # discard port; UDP connect transmits nothing
        return True
    except OSError:
        return False
    finally:
        sock.close()


@dataclass
class ConnectionStats:
    state: str = "DISCONNECTED"
    virtual_ip: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    connected_since: float | None = None


class HandshakeMonitor:
    """Track TLS handshake progress from OpenVPN's log output.

    OpenVPN only reports a stalled handshake once its ``hand-window``
    (60 s by default) expires, and then retries forever. Following the log
    lets the UI warn early and explain where the handshake stopped.
    """

    NO_REPLY = "no_reply"
    SERVER_REPLIED = "server_replied"
    SERVER_VERIFIED = "server_verified"
    DONE = "done"

    def __init__(self) -> None:
        self.phase = self.NO_REPLY
        self.failed = False
        self._verified_at: float | None = None

    def feed(self, line: str, now: float) -> None:
        if "Peer Connection Initiated" in line:
            self.phase = self.DONE
        elif "TLS key negotiation failed" in line or "TLS handshake failed" in line:
            self.failed = True
        elif "VERIFY OK: depth=0" in line:
            self.phase = self.SERVER_VERIFIED
            self._verified_at = now
        elif "TLS: Initial packet from" in line and self.phase == self.NO_REPLY:
            self.phase = self.SERVER_REPLIED

    def stalled(self, now: float) -> bool:
        """True once the server has gone quiet after sending its certificate."""
        return (
            self.phase == self.SERVER_VERIFIED
            and self._verified_at is not None
            and now - self._verified_at >= HANDSHAKE_STALL_SEC
        )

    def failure_message(self) -> str:
        if self.phase == self.SERVER_VERIFIED:
            return (
                "TLS handshake failed: the server sent a valid certificate, then "
                "stopped responding after receiving this profile's client "
                "certificate.\n\nThe server is most likely rejecting the client "
                "certificate: it may be revoked, the server's CRL may have "
                "expired, or the server's PKI was regenerated. Check the "
                "server's OpenVPN log for \"VERIFY ERROR\" or \"CRL\"."
            )
        if self.phase == self.SERVER_REPLIED:
            return (
                "TLS handshake failed: the server answered but the handshake "
                "did not complete. Check the server's OpenVPN log for the reason."
            )
        return (
            "TLS handshake failed: no reply from the server. Check that it is "
            "running and reachable on this port, and that the profile's "
            "tls-auth / tls-crypt key matches the server's."
        )


class ManagementClient:
    """Talk to OpenVPN management interface (Unix socket or TCP)."""

    def __init__(
        self,
        *,
        unix_path: Path | None = None,
        host: str = MANAGEMENT_HOST,
        port: int = 0,
    ) -> None:
        self._unix_path = unix_path
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None
        self._buf = b""

    def _target_label(self) -> str:
        if self._unix_path:
            return str(self._unix_path)
        return f"{self._host}:{self._port}"

    def connect(
        self, timeout: float = 30.0, should_cancel: Callable[[], bool] | None = None
    ) -> None:
        deadline = time.monotonic() + timeout
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            if should_cancel and should_cancel():
                raise InterruptedError("Connection cancelled")
            try:
                if self._unix_path:
                    if not self._unix_path.exists():
                        raise OSError("socket not created yet")
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect(os_fspath(self._unix_path))
                else:
                    sock = socket.create_connection(
                        (self._host, self._port), timeout=2.0
                    )
                    sock.settimeout(5.0)
                self._sock = sock
                self._buf = b""
                self._read_greeting()
                return
            except OSError as e:
                last_err = e
                time.sleep(0.25)
        raise ConnectionError(
            f"Could not connect to management interface ({self._target_label()}). "
            "OpenVPN may have failed to start — check the log above."
        ) from last_err

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._buf = b""

    def _read_line(self) -> str | None:
        """Return the next line from the socket, or None on EOF."""
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096) if self._sock else b""
            if not chunk:
                return None
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("utf-8", errors="replace").rstrip("\r")

    def _read_greeting(self, timeout: float = 5.0) -> None:
        """Consume the ``>INFO:`` banner OpenVPN sends on connect."""
        if not self._sock:
            return
        self._sock.settimeout(timeout)
        try:
            self._read_line()
        except OSError:
            pass

    def _read_response(self, timeout: float = 5.0) -> str:
        """Read one command reply plus any interleaved notifications.

        The management protocol has no prompt: a reply is a single
        ``SUCCESS:``/``ERROR:`` line or a block ending in ``END``, and
        real-time ``>`` notifications may arrive in between. Stopping on those
        terminators avoids waiting out the socket timeout on every command.
        """
        if not self._sock:
            return ""
        self._sock.settimeout(timeout)
        lines: list[str] = []
        try:
            while True:
                line = self._read_line()
                if line is None:
                    break
                lines.append(line)
                if line == "END" or line.startswith(("SUCCESS:", "ERROR:")):
                    break
        except OSError:
            pass
        return "\n".join(lines)

    def command(self, cmd: str) -> str:
        if not self._sock:
            raise RuntimeError("Not connected to management interface")
        self._sock.sendall((cmd.strip() + "\n").encode("utf-8"))
        return self._read_response()

    def send_credentials(self, username: str, password: str) -> None:
        # Strip CR/LF so a value can't inject additional management commands.
        user = username.replace("\r", "").replace("\n", "")
        secret = password.replace("\r", "").replace("\n", "")
        self.command(f'username "Auth" {user}')
        self.command(f'password "Auth" {secret}')

    def signal_stop(self) -> None:
        """Ask OpenVPN to exit via management interface."""
        try:
            if self._sock:
                self._sock.settimeout(1.0)
            self.command("signal SIGTERM")
        except (OSError, RuntimeError):
            pass


class VpnWorker(QThread):
    """Background thread: launch openvpn and poll management interface."""

    status_changed = Signal(str)
    stats_updated = Signal(object)
    log_line = Signal(str)
    connected = Signal()
    disconnected = Signal(str)
    error = Signal(str)
    stop_requested = Signal()

    def __init__(
        self,
        config_path: Path,
        management_port: int,
        username: str = "",
        password: str = "",
        allow_scripts: bool = False,
        route_all_traffic: bool = False,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._config_path = config_path
        self._management_port = management_port
        self._username = username
        self._password = password
        self._allow_scripts = allow_scripts
        self._route_all_traffic = route_all_traffic
        self._stop = False
        self._process: subprocess.Popen[str] | None = None
        self._mgmt: ManagementClient | None = None
        self._auth_file: Path | None = None
        self._mgmt_socket: Path | None = None
        self._output_thread: threading.Thread | None = None
        self._handshake = HandshakeMonitor()
        self.stop_requested.connect(
            self._apply_stop, Qt.ConnectionType.QueuedConnection
        )

    def request_stop(self) -> None:
        """Request shutdown from the UI thread (non-blocking)."""
        self._stop = True
        self.stop_requested.emit()

    @Slot()
    def _apply_stop(self) -> None:
        """Run on the worker thread: stop OpenVPN and unblock I/O."""
        if self._mgmt:
            self._mgmt.signal_stop()
            self._mgmt.close()
        pid_file = self._pid_file_path()
        if pid_file.is_file():
            try:
                ovpn_pid = int(pid_file.read_text(encoding="utf-8").strip())
                if needs_elevation():
                    subprocess.run(
                        ["sudo", "-n", "kill", str(ovpn_pid)],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                else:
                    os_kill(ovpn_pid, signal.SIGTERM)
            except (OSError, ValueError):
                pass
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
            except OSError:
                pass

    def _mgmt_socket_path(self) -> Path:
        path = _runtime_dir() / f"mgmt-{os_getpid()}-{time.time_ns()}.sock"
        path.unlink(missing_ok=True)
        return path

    def _build_command(self, mgmt_socket: Path) -> list[str]:
        user = getpass.getuser()
        args = [
            openvpn_binary(),
            "--disable-dco",
            "--config",
            str(self._config_path),
            "--management",
            os_fspath(mgmt_socket),
            "unix",
            "--management-client-user",
            user,
            "--management-query-passwords",
            "--management-hold",
            "--verb",
            "3",
            "--writepid",
            os_fspath(self._pid_file_path()),
        ]
        if self._username and self._password:
            # Place the credential file in the 0700 per-user runtime dir rather
            # than world-traversable /tmp. mkstemp creates it 0600.
            fd, path = tempfile.mkstemp(
                prefix="ovpn-auth-", suffix=".txt", dir=os_fspath(_runtime_dir())
            )
            os_close(fd)
            self._auth_file = Path(path)
            self._auth_file.write_text(
                f"{self._username}\n{self._password}\n", encoding="utf-8"
            )
            self._auth_file.chmod(0o600)
            args.extend(["--auth-user-pass", str(self._auth_file)])
        forced_proto = self._preferred_ipv4_proto()
        if forced_proto:
            args.extend(["--proto", forced_proto])
        if not self._allow_scripts:
            # Neutralize root code-execution from config-embedded scripts
            # (up/down/tls-verify/…). Appended after --config so it overrides
            # any higher script-security the config tries to set. Level 1 still
            # permits OpenVPN's own built-in ifconfig/route helpers.
            args.extend(["--script-security", "1"])
        if not self._route_all_traffic:
            # Split tunnel: keep the host's own default route and only reach
            # the networks the server pushes explicit routes for.
            self.log_line.emit(
                "Split tunnel: ignoring server-pushed default routes — "
                "internet traffic stays on the local connection"
            )
            for option in FULL_TUNNEL_PUSH_OPTIONS:
                args.extend(["--pull-filter", "ignore", option])
        args.extend(["--dev", "tun"])
        return wrap_openvpn_command(args)

    def _remote_target(self) -> tuple[str, str]:
        """Return (host, proto) for the first ``remote`` in the config."""
        host, proto = "", "udp"
        try:
            text = self._config_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return host, proto
        for raw in text.splitlines():
            line = raw.strip()
            low = line.lower()
            if low.startswith("remote "):
                parts = line.split()
                if len(parts) >= 2 and not host:
                    host = parts[1]
                if len(parts) >= 4:
                    proto = parts[3].lower()
            elif low.startswith("proto "):
                parts = line.split()
                if len(parts) >= 2:
                    proto = parts[1].lower()
        return host, proto

    def _preferred_ipv4_proto(self) -> str | None:
        """Force IPv4 when native IPv4 can reach the server.

        On dual-stack hosts whose resolver does DNS64, OpenVPN may dial the
        server over a synthesized NAT64 IPv6 address that silently drops the
        UDP handshake. When the server has a real A record and we have a
        native IPv4 route to it, force IPv4 (e.g. ``udp4``) so the tunnel
        actually comes up. Genuinely IPv6-only / NAT64-only networks have no
        IPv4 route here, so they are left untouched.
        """
        host, proto = self._remote_target()
        if not host:
            return None
        # Respect explicit IP literals; only hostnames suffer the DNS64 issue.
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, host)
                return None
            except OSError:
                pass
        try:
            ipv4 = _resolve_ipv4(host)
            if not ipv4 or not _ipv4_route_available(ipv4):
                return None
        except OSError:
            return None
        forced = "tcp4" if proto.startswith("tcp") else "udp4"
        self.log_line.emit(
            f"Native IPv4 route to {host} ({ipv4}) detected — forcing "
            f"{forced} to avoid a broken NAT64/IPv6 path"
        )
        return forced

    def _pid_file_path(self) -> Path:
        return _runtime_dir() / f"openvpn-{os_getpid()}.pid"

    def _cleanup_auth_file(self) -> None:
        if self._auth_file and self._auth_file.is_file():
            try:
                self._auth_file.unlink()
            except OSError:
                pass
            self._auth_file = None

    def _parse_state(self, response: str) -> str:
        """Return the most recent OpenVPN state name.

        Handles both the asynchronous real-time notification form
        (``>STATE:<time>,CONNECTED,...``) and the ``state`` command
        response form, whose history lines have no ``>STATE:`` prefix
        (``<time>,CONNECTED,SUCCESS,...``) and end with ``END``.
        """
        state = ""
        for raw in response.splitlines():
            line = raw.strip()
            if not line or line == "END":
                continue
            if line.startswith(">STATE:"):
                line = line[len(">STATE:"):]
            elif line.startswith(">"):
                continue  # other real-time notification (BYTECOUNT, LOG, …)
            parts = line.split(",")
            if len(parts) >= 2 and parts[0].isdigit() and parts[1].strip():
                state = parts[1].strip()  # keep the last (newest) entry
        return state

    def _parse_bytecount(self, response: str) -> tuple[int, int] | None:
        for line in response.splitlines():
            if line.startswith(">BYTECOUNT:"):
                parts = line.split(":")
                if len(parts) >= 2:
                    nums = parts[1].split(",")
                    if len(nums) >= 2:
                        return int(nums[0]), int(nums[1])
            elif line.startswith("BYTECOUNT:"):
                nums = line.split(":")[1].strip().split(",")
                if len(nums) >= 2:
                    return int(nums[0]), int(nums[1])
        return None

    def _start_output_reader(self) -> None:
        """Drain openvpn stdout so the child cannot block on a full pipe."""
        proc = self._process
        if not proc or not proc.stdout:
            return

        def _read() -> None:
            try:
                for line in proc.stdout:
                    if self._stop:
                        break
                    text = line.rstrip()
                    if text:
                        self._handshake.feed(text, time.monotonic())
                        self.log_line.emit(text)
            except (OSError, ValueError):
                pass

        self._output_thread = threading.Thread(target=_read, daemon=True)
        self._output_thread.start()

    def _interruptible_sleep(self, seconds: float) -> None:
        """Sleep in small steps so stop requests are picked up quickly."""
        end = time.monotonic() + seconds
        while time.monotonic() < end and not self._stop:
            time.sleep(min(0.2, end - time.monotonic()))

    def _parse_virtual_ip(self, response: str) -> str:
        """Return the tunnel address from the newest CONNECTED state line.

        State lines are ``time,state,desc,local-tun-ipv4,remote-addr,
        remote-port,local-addr,local-port,local-tun-ipv6``; the IPv6 tunnel
        address is used only when there is no IPv4 one.
        """
        vip = ""
        for raw in response.splitlines():
            line = raw.strip()
            if line.startswith(">STATE:"):
                line = line[len(">STATE:"):]
            parts = line.split(",")
            if len(parts) < 4 or not parts[0].isdigit() or parts[1] != "CONNECTED":
                continue
            ipv4 = parts[3].strip()
            ipv6 = parts[8].strip() if len(parts) > 8 else ""
            vip = ipv4 or ipv6 or vip
        return vip

    @Slot()
    def run(self) -> None:
        self._mgmt_socket = self._mgmt_socket_path()
        stats = ConnectionStats(state="CONNECTING")
        self.status_changed.emit(stats.state)

        try:
            if needs_elevation() and not sudo_ticket_valid():
                raise RuntimeError(
                    "Administrator access expired. Connect again and enter your "
                    "login password when prompted."
                )
            cmd = self._build_command(self._mgmt_socket)
            self.log_line.emit(
                "Launching: "
                + " ".join(cmd[:3])
                + (" …" if len(cmd) > 3 else "")
            )
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self._start_output_reader()

            self._interruptible_sleep(0.5)
            if self._process.poll() is not None:
                code = self._process.returncode
                raise RuntimeError(
                    f"OpenVPN exited immediately (code {code}). "
                    "Check the log above (sudo cache may have expired)."
                )

            self.log_line.emit(f"Waiting for management socket: {self._mgmt_socket}")
            self._mgmt = ManagementClient(unix_path=self._mgmt_socket)
            self._mgmt.connect(
                timeout=CONNECT_TIMEOUT_SEC, should_cancel=lambda: self._stop
            )
            self.log_line.emit("Management interface connected")

            hold_resp = self._mgmt.command("hold release")
            self.log_line.emit(hold_resp.strip()[:120] if hold_resp else "")

            if self._username and self._password and not self._auth_file:
                self._mgmt.send_credentials(self._username, self._password)

            self._mgmt.command("bytecount 2")
            connected_at: float | None = None
            last_state = ""
            stall_reported = False

            while not self._stop:
                if self._process.poll() is not None:
                    code = self._process.returncode
                    self.error.emit(f"OpenVPN exited (code {code})")
                    break

                # Before the first CONNECTED, a TLS failure would otherwise
                # retry forever with no explanation. Afterwards, let OpenVPN
                # ride out transient reconnect failures on its own.
                if connected_at is None:
                    if self._handshake.failed:
                        self.error.emit(self._handshake.failure_message())
                        break
                    if not stall_reported and self._handshake.stalled(
                        time.monotonic()
                    ):
                        stall_reported = True
                        self.log_line.emit(
                            f"No reply from the server {HANDSHAKE_STALL_SEC:.0f} s "
                            "after its certificate was verified — it may be "
                            "rejecting this client's certificate. OpenVPN gives "
                            "up when its handshake window expires (60 s by "
                            "default)."
                        )

                try:
                    state_resp = self._mgmt.command("state")
                    state = self._parse_state(state_resp) or last_state
                    if state and state != last_state:
                        last_state = state
                        stats.state = state
                        self.status_changed.emit(state)
                        self.log_line.emit(f"State: {state}")
                        if state == "CONNECTED" and connected_at is None:
                            connected_at = time.monotonic()
                            self.connected.emit()

                    # ">BYTECOUNT:" notifications (enabled by "bytecount 2")
                    # arrive interleaved with command replies.
                    counts = self._parse_bytecount(state_resp)
                    if counts:
                        stats.bytes_in, stats.bytes_out = counts
                    stats.connected_since = connected_at

                    if state == "CONNECTED":
                        vip = self._parse_virtual_ip(state_resp)
                        if vip:
                            stats.virtual_ip = vip

                    stats.state = state or stats.state
                    self.stats_updated.emit(stats)
                except (OSError, RuntimeError) as e:
                    if not self._stop:
                        self.log_line.emit(f"Management error: {e}")
                    break

                self._interruptible_sleep(POLL_INTERVAL_SEC)

        except InterruptedError:
            self.log_line.emit("Connection stopped by user")
        except Exception as e:
            if not self._stop:
                self.error.emit(str(e))
        finally:
            self._cleanup_auth_file()
            if self._mgmt:
                self._mgmt.close()
            if self._process and self._process.poll() is None:
                try:
                    self._process.terminate()
                    self._process.wait(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    try:
                        self._process.kill()
                    except OSError:
                        pass
            self.disconnected.emit(stats.state)
            self._process = None
            self._mgmt = None
            if self._mgmt_socket:
                self._mgmt_socket.unlink(missing_ok=True)
                self._mgmt_socket = None


def wireguard_interface_name(profile_id: str) -> str:
    """Kernel interface name for a profile (wg-quick: ≤15 chars, from filename)."""
    stem = "".join(c for c in profile_id if c.isalnum())[:8] or "0"
    return f"wgm-{stem}"


class WireGuardWorker(QThread):
    """Background thread: bring a WireGuard interface up with wg-quick and
    report traffic from sysfs until stopped.

    Exposes the same signals as ``VpnWorker`` so the controller and UI treat
    both tunnel types alike.
    """

    status_changed = Signal(str)
    stats_updated = Signal(object)
    log_line = Signal(str)
    connected = Signal()
    disconnected = Signal(str)
    error = Signal(str)

    def __init__(
        self,
        profile_id: str,
        config_path: Path,
        allow_scripts: bool = False,
        route_all_traffic: bool = False,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._config_path = config_path
        self._allow_scripts = allow_scripts
        self._route_all_traffic = route_all_traffic
        self._ifname = wireguard_interface_name(profile_id)
        self._runtime_conf: Path | None = None
        self._stop = False

    def request_stop(self) -> None:
        """Request shutdown from the UI thread (non-blocking)."""
        self._stop = True

    def _interface_exists(self) -> bool:
        return (SYS_CLASS_NET / self._ifname).exists()

    def _read_counter(self, name: str) -> int:
        try:
            path = SYS_CLASS_NET / self._ifname / "statistics" / name
            return int(path.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return 0

    def _write_runtime_config(self) -> str:
        """Install the wg-quick config as root-owned 0600 in /etc/wireguard.

        Distro MAC policies confine wg-quick to its config directory (Ubuntu's
        AppArmor profile only allows ``/etc/wireguard/**``), so it can't read a
        file from the user's runtime dir. The text is piped through ``install``
        on stdin so the private key never lands in a user-owned file.
        """
        content = self._config_path.read_text(encoding="utf-8", errors="replace")
        text, notes = build_runtime_config(
            content, self._route_all_traffic, self._allow_scripts
        )
        for note in notes:
            self.log_line.emit(note)
        path = WG_CONFIG_DIR / f"{self._ifname}.conf"
        if not (
            self._run_root(["install", "-d", "-m", "700", os_fspath(WG_CONFIG_DIR)])
            and self._run_root(
                ["install", "-m", "600", "/dev/stdin", os_fspath(path)],
                input_text=text,
            )
        ):
            raise RuntimeError(f"Could not write WireGuard config {path}")
        self._runtime_conf = path
        return content

    def _run_root(
        self,
        args: list[str],
        input_text: str | None = None,
        timeout: float = WG_QUICK_TIMEOUT_SEC,
    ) -> bool:
        """Run a command as root (sudo -n when needed), logging its output."""
        try:
            result = subprocess.run(
                wrap_root_command(args),
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.log_line.emit(f"{Path(args[0]).name} {args[1]} timed out")
            return False
        for line in (result.stdout + result.stderr).splitlines():
            if line.strip():
                self.log_line.emit(line.rstrip())
        return result.returncode == 0

    def _wg_quick(self, action: str) -> bool:
        """Run ``wg-quick up|down`` on the installed config."""
        assert self._runtime_conf is not None
        return self._run_root(
            [wg_quick_binary(), action, os_fspath(self._runtime_conf)]
        )

    def _cleanup_runtime_config(self) -> None:
        if self._runtime_conf:
            self._run_root(["rm", "-f", os_fspath(self._runtime_conf)], timeout=10)
            self._runtime_conf = None

    @Slot()
    def run(self) -> None:
        stats = ConnectionStats(state="CONNECTING")
        self.status_changed.emit(stats.state)
        brought_up = False

        try:
            if needs_elevation() and not sudo_ticket_valid():
                raise RuntimeError(
                    "Administrator access expired. Connect again and enter your "
                    "login password when prompted."
                )
            content = self._write_runtime_config()
            if self._interface_exists():
                # Left over from a crash or a session the app lost track of.
                self.log_line.emit(f"Removing stale interface {self._ifname}")
                self._wg_quick("down")
            self.log_line.emit(f"Launching: wg-quick up {self._ifname}")
            if not self._wg_quick("up"):
                raise RuntimeError(
                    "wg-quick could not bring the tunnel up. Check the log above."
                )
            brought_up = True
            if self._stop:
                return

            connected_at = time.monotonic()
            stats.state = "CONNECTED"
            stats.connected_since = connected_at
            stats.virtual_ip = first_address(content)
            self.status_changed.emit(stats.state)
            self.log_line.emit("State: CONNECTED")
            self.connected.emit()
            rx_warned = False

            while not self._stop:
                if not self._interface_exists():
                    brought_up = False
                    self.error.emit(
                        f"WireGuard interface {self._ifname} went away"
                    )
                    break
                stats.bytes_in = self._read_counter("rx_bytes")
                stats.bytes_out = self._read_counter("tx_bytes")
                self.stats_updated.emit(stats)
                if (
                    not rx_warned
                    and stats.bytes_in == 0
                    and time.monotonic() - connected_at >= WG_NO_RX_WARN_SEC
                ):
                    rx_warned = True
                    self.log_line.emit(
                        f"Nothing received from the peer {WG_NO_RX_WARN_SEC:.0f} s "
                        "after the tunnel came up — check that the endpoint is "
                        "reachable and that the keys match the server's."
                    )
                end = time.monotonic() + POLL_INTERVAL_SEC
                while time.monotonic() < end and not self._stop:
                    time.sleep(0.2)

        except Exception as e:
            if not self._stop:
                self.error.emit(str(e))
        finally:
            if brought_up and self._runtime_conf:
                self.log_line.emit(f"Stopping: wg-quick down {self._ifname}")
                if not self._wg_quick("down"):
                    self.error.emit(
                        f"Could not remove WireGuard interface {self._ifname}. "
                        f"Run: sudo ip link delete {self._ifname}"
                    )
            self._cleanup_runtime_config()
            self.disconnected.emit(stats.state)


class VpnController(QObject):
    """High-level VPN session controller for the UI."""

    status_changed = Signal(str)
    stats_updated = Signal(object)
    log_line = Signal(str)
    connected = Signal()
    disconnected = Signal()
    error = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._worker: VpnWorker | WireGuardWorker | None = None
        self._active_profile_id: str | None = None
        self._active_vpn_type = "openvpn"
        self._pending_connect: tuple[str, Path, str, str, bool, bool, str] | None = None
        self._tunnel_connected = False

    @property
    def is_connected(self) -> bool:
        """True while a session worker is running (not necessarily up)."""
        return self._worker is not None and self._worker.isRunning()

    @property
    def is_tunnel_connected(self) -> bool:
        """True only once OpenVPN reports the tunnel is fully CONNECTED."""
        return self._tunnel_connected

    @property
    def active_profile_id(self) -> str | None:
        return self._active_profile_id

    @property
    def active_needs_root_to_stop(self) -> bool:
        """True when stopping the session runs a root command (wg-quick down).

        OpenVPN stops through its management socket; WireGuard needs a valid
        sudo ticket, so the UI must refresh it before disconnecting.
        """
        return self.is_connected and self._active_vpn_type == "wireguard"

    def connect_profile(
        self,
        profile_id: str,
        config_path: Path,
        username: str = "",
        password: str = "",
        allow_scripts: bool = False,
        route_all_traffic: bool = False,
        vpn_type: str = "openvpn",
    ) -> None:
        if self._worker and self._worker.isRunning():
            self._pending_connect = (
                profile_id,
                config_path,
                username,
                password,
                allow_scripts,
                route_all_traffic,
                vpn_type,
            )
            self.disconnect()
            return
        self._start_worker(
            profile_id,
            config_path,
            username,
            password,
            allow_scripts,
            route_all_traffic,
            vpn_type,
        )

    def _start_worker(
        self,
        profile_id: str,
        config_path: Path,
        username: str,
        password: str,
        allow_scripts: bool = False,
        route_all_traffic: bool = False,
        vpn_type: str = "openvpn",
    ) -> None:
        self._active_profile_id = profile_id
        self._active_vpn_type = vpn_type
        self._tunnel_connected = False
        if vpn_type == "wireguard":
            self._worker = WireGuardWorker(
                profile_id,
                config_path,
                allow_scripts=allow_scripts,
                route_all_traffic=route_all_traffic,
            )
        else:
            self._worker = VpnWorker(
                config_path,
                0,
                username,
                password,
                allow_scripts=allow_scripts,
                route_all_traffic=route_all_traffic,
            )
        self._worker.status_changed.connect(self._on_worker_status)
        self._worker.stats_updated.connect(self.stats_updated.emit)
        self._worker.log_line.connect(self.log_line.emit)
        self._worker.connected.connect(self.connected.emit)
        self._worker.disconnected.connect(self._on_worker_disconnected)
        self._worker.error.connect(self.error.emit)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def disconnect(self, wait_ms: int = 0) -> None:
        """Stop VPN without blocking the UI (unless wait_ms > 0 for app exit)."""
        worker = self._worker
        if not worker:
            return
        if worker.isRunning():
            self.status_changed.emit("DISCONNECTING")
            worker.request_stop()
            if wait_ms > 0:
                worker.wait(wait_ms)
                self._clear_worker()
        else:
            self._clear_worker()

    def _clear_worker(self) -> None:
        self._worker = None
        self._active_profile_id = None
        self._tunnel_connected = False

    def _on_worker_status(self, state: str) -> None:
        # Keep the authoritative tunnel state in sync with what OpenVPN
        # reports so the UI never shows "Connected" before the tunnel is up
        # (or after it drops into RECONNECTING).
        self._tunnel_connected = state == "CONNECTED"
        self.status_changed.emit(state)

    def _on_worker_disconnected(self, _state: str) -> None:
        pass

    def _on_worker_finished(self) -> None:
        pending = self._pending_connect
        self._pending_connect = None
        self._clear_worker()
        self.disconnected.emit()
        if pending:
            self._start_worker(*pending)
