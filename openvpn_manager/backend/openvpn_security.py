"""Detect OpenVPN settings that leave the tunnel unencrypted or weakly protected.

Two layers: ``audit_config`` rejects a profile before OpenVPN starts, and
``SecurityMonitor`` reads OpenVPN's log to catch what was actually negotiated
with the server (which a config alone cannot show, e.g. a ``BF-CBC`` fallback).
"""

from __future__ import annotations

import re

# Ciphers with no encryption or a 64-bit block size (SWEET32).
WEAK_CIPHER_PREFIXES = ("NONE", "BF-", "DES", "RC2", "RC4", "CAST5", "IDEA", "DESX")
# HMAC digests that don't authenticate packets, or are broken.
WEAK_DIGESTS = ("NONE", "MD4", "MD5")
# OpenSSL cipher-string tokens for TLS suites with no or broken protection.
WEAK_TLS_CIPHER_TOKENS = (
    "NULL", "ANULL", "ENULL", "EXPORT", "EXP", "RC4", "DES", "3DES", "MD5",
)
WEAK_TLS_VERSIONS = ("1.0", "1.1")
# Any of these makes the client check the server certificate's identity;
# without one, any client of the same CA can impersonate the server.
SERVER_VERIFY_DIRECTIVES = (
    "remote-cert-tls",
    "verify-x509-name",
    "tls-verify",
    "peer-fingerprint",
    "ns-cert-type",
)

_DATA_CIPHER_RE = re.compile(
    r"Data Channel: (?:using negotiated )?cipher '([^']+)'(?:, auth '([^']+)')?",
    re.IGNORECASE,
)
_HMAC_RE = re.compile(r"Data Channel: Using \d+ bit message hash '([^']+)'")
_CONTROL_TLS_RE = re.compile(r"Control Channel: (TLSv1(?:\.\d)?|SSLv\d)\b")


def is_weak_cipher(name: str) -> bool:
    return name.strip().upper().startswith(WEAK_CIPHER_PREFIXES)


def is_weak_digest(name: str) -> bool:
    return name.strip().upper() in WEAK_DIGESTS


def _directives(text: str) -> tuple[list[list[str]], set[str]]:
    """Return (directive token lists, inline block tags) from a config.

    Inline block bodies (``<ca>…</ca>``) are skipped so key material is
    never mistaken for directives.
    """
    lines: list[list[str]] = []
    blocks: set[str] = set()
    in_block = ""
    for raw in text.splitlines():
        line = raw.strip()
        if in_block:
            if line.lower() == f"</{in_block}>":
                in_block = ""
            continue
        if line.startswith("<") and line.endswith(">") and not line.startswith("</"):
            in_block = line[1:-1].strip().lower()
            blocks.add(in_block)
            continue
        if not line or line.startswith(("#", ";")):
            continue
        parts = [p.strip("\"'") for p in line.split()]
        parts[0] = parts[0].lower().lstrip("-")
        lines.append(parts)
    return lines, blocks


def audit_config(text: str) -> list[str]:
    """Return a description of each insecure setting in an OpenVPN config."""
    problems: list[str] = []
    directives, blocks = _directives(text)
    names = {d[0] for d in directives} | blocks

    for parts in directives:
        name, args = parts[0], parts[1:]
        if name in ("cipher", "data-ciphers-fallback") and args:
            if is_weak_cipher(args[0]):
                problems.append(_cipher_problem(name, args[0]))
        elif name in ("data-ciphers", "ncp-ciphers") and args:
            for cipher in args[0].split(":"):
                if is_weak_cipher(cipher):
                    problems.append(_cipher_problem(name, cipher))
        elif name == "auth" and args and is_weak_digest(args[0]):
            problems.append(
                f"'auth {args[0]}': packets are not reliably authenticated, so "
                "tunnel traffic can be tampered with."
            )
        elif name == "tls-cipher" and args:
            # "!aNULL" / "-MD5" exclude a suite; only allowed entries count.
            words = {
                word
                for entry in args[0].upper().split(":")
                if entry and entry[0] not in "!-"
                for word in re.split(r"[-_+]", entry)
            }
            weak = sorted(words & set(WEAK_TLS_CIPHER_TOKENS))
            if weak:
                problems.append(
                    f"'tls-cipher {args[0]}' allows insecure TLS suites "
                    f"({', '.join(weak)})."
                )
        elif name in ("tls-version-min", "tls-version-max") and args:
            if args[0] in WEAK_TLS_VERSIONS:
                problems.append(
                    f"'{name} {args[0]}' allows TLS {args[0]}, which is "
                    "deprecated and insecure. Use TLS 1.2 or later."
                )
        elif name == "secret":
            problems.append(_STATIC_KEY_PROBLEM)
    if "secret" in blocks and _STATIC_KEY_PROBLEM not in problems:
        problems.append(_STATIC_KEY_PROBLEM)

    is_tls_client = "client" in names or "tls-client" in names
    if is_tls_client and not names & set(SERVER_VERIFY_DIRECTIVES):
        problems.append(
            "The server's certificate identity is not verified (no "
            "'remote-cert-tls server' or 'verify-x509-name'), so another "
            "client of the same CA could impersonate the server."
        )
    return problems


_STATIC_KEY_PROBLEM = (
    "'secret' (static-key mode): one long-lived key encrypts all traffic, "
    "with no TLS and no forward secrecy."
)


def _cipher_problem(directive: str, cipher: str) -> str:
    if cipher.strip().upper() == "NONE":
        return f"'{directive}' allows 'none': tunnel traffic would not be encrypted."
    return (
        f"'{directive}' allows {cipher}, a 64-bit block cipher vulnerable to "
        "SWEET32. Use AES-256-GCM, AES-128-GCM or CHACHA20-POLY1305."
    )


class SecurityMonitor:
    """Spot insecure settings in OpenVPN's log as the session negotiates them."""

    def __init__(self) -> None:
        self.problem = ""
        self.data_cipher = ""

    def feed(self, line: str) -> None:
        if self.problem:
            return
        if "NO encryption will be performed" in line:
            self.problem = "Insecure tunnel: OpenVPN reports traffic is NOT encrypted (cipher none)."
        elif "'--auth none' was specified" in line:
            self.problem = "Insecure tunnel: OpenVPN reports packets are NOT authenticated (auth none)."
        elif "INSECURE cipher" in line:
            self.problem = f"Insecure tunnel: weak cipher in use. OpenVPN says: {line.strip()}"
        elif "No server certificate verification method has been enabled" in line:
            self.problem = (
                "Insecure tunnel: the server's certificate identity is not "
                "verified, so the connection is open to impersonation. Add "
                "'remote-cert-tls server' to the profile."
            )
        elif m := _DATA_CIPHER_RE.search(line):
            cipher, digest = m.group(1), m.group(2) or ""
            self.data_cipher = cipher
            if is_weak_cipher(cipher):
                self.problem = f"Insecure tunnel: server negotiated weak data cipher {cipher}."
            elif digest and is_weak_digest(digest):
                self.problem = f"Insecure tunnel: server negotiated weak packet authentication {digest}."
        elif m := _HMAC_RE.search(line):
            if is_weak_digest(m.group(1)):
                self.problem = f"Insecure tunnel: server negotiated weak packet authentication {m.group(1)}."
        elif m := _CONTROL_TLS_RE.search(line):
            version = m.group(1)
            if version.startswith("SSL") or version in ("TLSv1", "TLSv1.0", "TLSv1.1"):
                self.problem = f"Insecure tunnel: control channel uses {version}; TLS 1.2 or later is required."
