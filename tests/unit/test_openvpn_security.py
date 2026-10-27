"""Unit tests for insecure OpenVPN config / negotiation detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from openvpn_manager.backend.openvpn_security import SecurityMonitor, audit_config
from openvpn_manager.backend.vpn_process import VpnWorker

SECURE = """\
client
dev tun
proto udp
remote vpn.example.com 1194
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:!aNULL:!MD5
<ca>
-----BEGIN CERTIFICATE-----
cipher none
-----END CERTIFICATE-----
</ca>
<tls-crypt>
secret-looking key material
</tls-crypt>
"""


def test_secure_config_has_no_problems() -> None:
    assert audit_config(SECURE) == []


@pytest.mark.parametrize(
    "line, fragment",
    [
        ("cipher none", "not be encrypted"),
        ("cipher BF-CBC", "SWEET32"),
        ("--cipher DES-EDE3-CBC", "SWEET32"),
        ("data-ciphers AES-256-GCM:BF-CBC", "BF-CBC"),
        ("data-ciphers-fallback BF-CBC", "BF-CBC"),
        ("ncp-ciphers AES-256-GCM:none", "not be encrypted"),
        ("auth none", "tampered"),
        ("auth MD5", "tampered"),
        ("tls-version-min 1.0", "TLS 1.0"),
        ("tls-version-max 1.1", "TLS 1.1"),
        ("tls-cipher DEFAULT:NULL-SHA", "NULL"),
        ("tls-cipher TLS-RSA-WITH-3DES-EDE-CBC-SHA", "3DES"),
        ("secret static.key", "static-key"),
    ],
)
def test_insecure_directive_is_reported(line: str, fragment: str) -> None:
    problems = audit_config(SECURE + line + "\n")
    assert len(problems) == 1
    assert fragment in problems[0]


def test_commented_out_directive_is_ignored() -> None:
    assert audit_config(SECURE + "# cipher none\n; auth none\n") == []


def test_inline_static_key_is_reported() -> None:
    config = "dev tun\nremote vpn.example.com\n<secret>\nkey\n</secret>\n"
    assert any("static-key" in p for p in audit_config(config))


def test_client_without_server_verification_is_reported() -> None:
    config = SECURE.replace("remote-cert-tls server\n", "")
    problems = audit_config(config)
    assert len(problems) == 1
    assert "impersonate" in problems[0]


@pytest.mark.parametrize(
    "directive",
    ["verify-x509-name vpn.example.com name", "peer-fingerprint AB:CD", "<peer-fingerprint>\nAB:CD\n</peer-fingerprint>"],
)
def test_alternative_server_verification_is_accepted(directive: str) -> None:
    config = SECURE.replace("remote-cert-tls server", directive)
    assert audit_config(config) == []


@pytest.mark.parametrize(
    "line",
    [
        "******* WARNING *******: '--cipher none' was specified. This means NO encryption will be performed",
        "******* WARNING *******: '--auth none' was specified. This means no authentication",
        "WARNING: INSECURE cipher (BF-CBC) with block size less than 128 bit (64 bit).",
        "WARNING: No server certificate verification method has been enabled.  See http://openvpn.net/howto.html#mitm",
        "Data Channel: cipher 'BF-CBC', auth 'SHA1', peer-id: 0",
        "Data Channel: cipher 'AES-256-CBC', auth 'MD5', peer-id: 0",
        "Data Channel: using negotiated cipher 'BF-CBC'",
        "Outgoing Data Channel: Using 128 bit message hash 'MD5' for HMAC authentication",
        "Control Channel: TLSv1.1, cipher TLSv1/SSLv3 ECDHE-RSA-AES256-SHA",
    ],
)
def test_monitor_flags_insecure_log_line(line: str) -> None:
    monitor = SecurityMonitor()
    monitor.feed(line)
    assert monitor.problem.startswith("Insecure tunnel")


@pytest.mark.parametrize(
    "line, cipher",
    [
        ("Data Channel: cipher 'AES-256-GCM', peer-id: 0", "AES-256-GCM"),
        ("Data Channel: using negotiated cipher 'CHACHA20-POLY1305'", "CHACHA20-POLY1305"),
        ("Data Channel: cipher 'AES-256-CBC', auth 'SHA256', peer-id: 0", "AES-256-CBC"),
    ],
)
def test_monitor_records_secure_cipher(line: str, cipher: str) -> None:
    monitor = SecurityMonitor()
    monitor.feed("Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384")
    monitor.feed(line)
    assert monitor.problem == ""
    assert monitor.data_cipher == cipher


def test_worker_refuses_insecure_profile(tmp_path: Path) -> None:
    config = tmp_path / "bad.ovpn"
    config.write_text(SECURE + "cipher none\n", encoding="utf-8")
    worker = VpnWorker(config, 0)
    with pytest.raises(RuntimeError, match="not secure"):
        worker._check_config_security()


def test_worker_accepts_secure_profile(tmp_path: Path) -> None:
    config = tmp_path / "good.ovpn"
    config.write_text(SECURE, encoding="utf-8")
    VpnWorker(config, 0)._check_config_security()
