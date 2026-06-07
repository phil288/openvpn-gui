"""Secure credential storage via system keyring."""

from __future__ import annotations

import keyring

SERVICE_NAME = "openvpn-manager"
ADMIN_PASSWORD_KEY = "admin:elevate"


def _username_key(profile_id: str) -> str:
    return f"{profile_id}:username"


def _password_key(profile_id: str) -> str:
    return f"{profile_id}:password"


def save_credentials(profile_id: str, username: str, password: str) -> None:
    keyring.set_password(SERVICE_NAME, _username_key(profile_id), username)
    keyring.set_password(SERVICE_NAME, _password_key(profile_id), password)


def load_credentials(profile_id: str) -> tuple[str, str] | None:
    username = keyring.get_password(SERVICE_NAME, _username_key(profile_id))
    password = keyring.get_password(SERVICE_NAME, _password_key(profile_id))
    if username is None and password is None:
        return None
    return (username or "", password or "")


def delete_credentials(profile_id: str) -> None:
    try:
        keyring.delete_password(SERVICE_NAME, _username_key(profile_id))
    except keyring.errors.PasswordDeleteError:
        pass
    try:
        keyring.delete_password(SERVICE_NAME, _password_key(profile_id))
    except keyring.errors.PasswordDeleteError:
        pass


def has_credentials(profile_id: str) -> bool:
    return load_credentials(profile_id) is not None


def delete_admin_password() -> None:
    """Remove any legacy stored login/sudo password.

    The app deliberately no longer persists the user's login password (it is a
    reusable account secret that any same-user process could read back from the
    keyring). This remains only to purge secrets written by older versions.
    """
    try:
        keyring.delete_password(SERVICE_NAME, ADMIN_PASSWORD_KEY)
    except keyring.errors.PasswordDeleteError:
        pass
