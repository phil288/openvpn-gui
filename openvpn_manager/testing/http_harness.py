"""Minimal HTTP server exposing app internals for automated E2E tests."""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from openvpn_manager.backend.profile_store import parse_ovpn_config
from openvpn_manager.backend.vpn_process import VpnWorker
from openvpn_manager.single_instance import ovpn_paths_from_argv


def _build_command_probe() -> dict[str, Any]:
    sock = Path(os.environ.get("OPENVPN_MANAGER_RUNTIME_DIR", "/tmp")) / "test-mgmt.sock"
    worker = VpnWorker(Path("/tmp/test.ovpn"), 0, "user", "pass")
    cmd = worker._build_command(sock)
    return {
        "ok": True,
        "command": cmd,
        "has_unix_management": "unix" in cmd,
        "has_management_client_user": "--management-client-user" in cmd,
        "has_auth_file": "--auth-user-pass" in cmd,
    }


class _HarnessHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/health":
                self._send_json(200, {"status": "ok"})
            elif path == "/api/build-command":
                self._send_json(200, _build_command_probe())
            elif path == "/api/parse-ovpn":
                sample = "remote vpn.example.com 1194 udp\nauth-user-pass\n"
                meta = parse_ovpn_config(sample)
                self._send_json(200, {"ok": True, "meta": meta})
            elif path == "/api/argv-ovpn":
                paths = ovpn_paths_from_argv(
                    ["openvpn-manager", "/tmp/a.ovpn", "--foo"]
                )
                self._send_json(
                    200,
                    {"ok": True, "paths": [str(p) for p in paths]},
                )
            else:
                self._send_json(404, {"error": "not found"})
        except Exception as exc:
            self._send_json(500, {"ok": False, "error": str(exc)})


def serve_forever(host: str = "127.0.0.1", port: int = 8765) -> HTTPServer:
    os.environ.setdefault(
        "OPENVPN_MANAGER_RUNTIME_DIR",
        str(Path(os.environ.get("TMPDIR", "/tmp")) / "openvpn-manager-test"),
    )
    Path(os.environ["OPENVPN_MANAGER_RUNTIME_DIR"]).mkdir(
        parents=True, exist_ok=True
    )
    server = HTTPServer((host, port), _HarnessHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> None:
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = serve_forever(port=port)
    print(f"Test harness listening on http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
