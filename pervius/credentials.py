"""Credentials: memory-only by default, desktop keyring when selected.

There is deliberately no plaintext fallback.  If the Secret Service is
unavailable or locked, the caller is told that persistence is unavailable and
the password can still be used for the current process only.

Python strings cannot be reliably zeroized, so this module does not claim to
erase every copy from memory.  It does guarantee that passwords are never
written to our logs or non-secret settings, and that a failed keyring store
does not silently degrade to a plaintext file.

Only the NetworkManager secret agent reads a stored password
(``lookup``).  The user interface asks ``password_state`` instead, which
reports whether a password exists without loading it, so a stored secret
never reaches a widget.
"""

from __future__ import annotations

import logging

import gi

gi.require_version("Secret", "1")
from gi.repository import Gio, GLib, Secret  # noqa: E402

from .config import (  # noqa: E402
    SECRET_PURPOSE,
    SECRET_SCHEMA_ATTRIBUTE_PURPOSE,
    SECRET_SCHEMA_ATTRIBUTE_USERNAME,
    SECRET_SCHEMA_NAME,
)

log = logging.getLogger(__name__)


class CredentialError(RuntimeError):
    pass


# Values returned by CredentialStore.password_state().
SAVED_IN_KEYRING = "keyring"
SESSION_ONLY = "session"


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

    def password_state(self, username: str) -> str | None:
        """Report where a password for ``username`` is kept, without reading it.

        Returns SESSION_ONLY for a password held in memory only,
        SAVED_IN_KEYRING when the keyring has an entry, or None.  The keyring
        search uses no LOAD_SECRETS/UNLOCK flags, so the secret value is never
        transferred to this process.
        """
        if not username:
            return None
        found_in_memory = username in self._memory
        if self._schema is not None:
            try:
                items = Secret.password_search_sync(
                    self._schema,
                    self._attributes(username),
                    Secret.SearchFlags.NONE,
                    None,
                )
            except GLib.Error as exc:
                log.warning("Secret Service search failed: %s", exc.message)
                items = []
            if items:
                return SAVED_IN_KEYRING
        return SESSION_ONLY if found_in_memory else None

    def lookup(self, username: str) -> str | None:
        """Return the password.  Only the secret agent may call this."""
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

    def lookup_async(self, username: str, callback, *, timeout: int = 25) -> None:
        """Look the password up without blocking the main loop.

        A locked keyring can show an unlock prompt and take a long time; the
        synchronous lookup would freeze the app meanwhile.  ``callback`` gets
        the password or None, exactly once, on the main loop, within
        ``timeout`` seconds.  Only the secret agent may call this.
        """
        if not username:
            GLib.idle_add(lambda: callback(None) and False)
            return
        if username in self._memory:
            value = self._memory[username]
            GLib.idle_add(lambda: callback(value) and False)
            return
        if self._schema is None:
            GLib.idle_add(lambda: callback(None) and False)
            return
        cancellable = Gio.Cancellable()
        state = {"done": False}

        def finish(value):
            if state["done"]:
                return
            state["done"] = True
            if value:
                self._memory[username] = value
            callback(value or None)

        def expire():
            if not state["done"]:
                log.warning("Secret Service lookup timed out")
                cancellable.cancel()
                finish(None)
            return False

        timer = GLib.timeout_add_seconds(timeout, expire)

        def done(_source, result, _data=None):
            GLib.source_remove(timer) if not state["done"] else None
            try:
                value = Secret.password_lookup_finish(result)
            except GLib.Error as exc:
                if not state["done"]:
                    log.warning("Secret Service lookup failed: %s", exc.message)
                value = None
            finish(value)

        try:
            Secret.password_lookup(self._schema, self._attributes(username), cancellable, done, None)
        except Exception as exc:  # pragma: no cover - host keyring
            log.warning("Secret Service lookup could not start: %s", exc)
            GLib.source_remove(timer)
            finish(None)

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
