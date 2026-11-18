"""Credentials: memory-only by default, desktop keyring when selected.

There is deliberately no plaintext fallback.  If the Secret Service is
unavailable or locked, the caller is told that persistence is unavailable and
the password can still be used for the current process only.

Python strings cannot be reliably zeroized, so this module does not claim to
erase every copy from memory.  It does guarantee that passwords are never
written to our logs or non-secret settings, and that a failed keyring store
does not silently degrade to a plaintext file.
"""

from __future__ import annotations

import logging

import gi

gi.require_version("Secret", "1")
from gi.repository import GLib, Secret  # noqa: E402

from .config import (  # noqa: E402
    SECRET_PURPOSE,
    SECRET_SCHEMA_ATTRIBUTE_PURPOSE,
    SECRET_SCHEMA_ATTRIBUTE_USERNAME,
    SECRET_SCHEMA_NAME,
)

log = logging.getLogger(__name__)


class CredentialError(RuntimeError):
    pass


class CredentialStore:
    def __init__(self, schema_name: str = SECRET_SCHEMA_NAME):
        self._memory: dict[str, str] = {}
        self._schema: Secret.Schema | None = None
        self._schema_error: str | None = None
        try:
            self._schema = Secret.Schema.new(
                schema_name,
                Secret.SchemaFlags.NONE,
                {
                    SECRET_SCHEMA_ATTRIBUTE_USERNAME: Secret.SchemaAttributeType.STRING,
                    SECRET_SCHEMA_ATTRIBUTE_PURPOSE: Secret.SchemaAttributeType.STRING,
                },
            )
            if self._schema is None:
                self._schema_error = "Secret Service schema could not be created"
        except Exception as exc:  # pragma: no cover - depends on host keyring
            self._schema_error = str(exc)

    @property
    def persistence_available(self) -> bool:
        return self._schema is not None

    @property
    def persistence_error(self) -> str | None:
        return self._schema_error

    def _attributes(self, username: str) -> dict[str, str]:
        return {
            SECRET_SCHEMA_ATTRIBUTE_USERNAME: username,
            SECRET_SCHEMA_ATTRIBUTE_PURPOSE: SECRET_PURPOSE,
        }

    def remember(self, username: str, password: str) -> None:
        if username:
            self._memory[username] = password

    def lookup(self, username: str) -> str | None:
        if not username:
            return None
        if username in self._memory:
            return self._memory[username]
        if self._schema is None:
            return None
        try:
            value = Secret.password_lookup_sync(self._schema, self._attributes(username), None)
        except GLib.Error as exc:
            log.warning("Secret Service lookup failed: %s", exc.message)
            return None
        if value:
            self._memory[username] = value
        return value or None

    def store(self, username: str, password: str, *, persist: bool) -> bool:
        """Keep a password for this session and optionally in the keyring.

        Returns True if the keyring write succeeded (or persistence was not
        requested).  Raises CredentialError when persistence was requested but
        could not be completed.
        """
        self.remember(username, password)
        if not persist:
            return True
        if self._schema is None:
            raise CredentialError(self._schema_error or "Secret Service is unavailable")
        try:
            ok = Secret.password_store_sync(
                self._schema,
                self._attributes(username),
                Secret.COLLECTION_DEFAULT,
                f"Pervius VPN password for {username}",
                password,
                None,
            )
        except GLib.Error as exc:
            raise CredentialError(f"could not save password in the keyring: {exc.message}") from exc
        if not ok:
            raise CredentialError("the keyring did not accept the password")
        return True

    def forget(self, username: str) -> bool:
        self._memory.pop(username, None)
        if self._schema is None or not username:
            return True
        try:
            return bool(
                Secret.password_clear_sync(self._schema, self._attributes(username), None)
            )
        except GLib.Error as exc:
            raise CredentialError(f"could not remove password from the keyring: {exc.message}") from exc
