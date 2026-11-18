"""One-time upgrade migration from the pre-rename 0.1.x releases.

Releases up to 0.1.19 shipped as "Solvetus VPN Manager".  This module is the
only place in the application that knows their identifiers.  It adopts, once:

1. **Files** — non-secret settings (including favorites), the ownership
   manifest, the cached catalogue and the imported CA file are copied from the
   old data directory into the new one.  The old directory is left in place.
2. **Keyring** — saved VPN passwords are copied from the old Secret Service
   schema to the new one, verified, and then the old entries are deleted.
   Secrets are never logged, printed or written anywhere else.
3. **Profile** — the app-owned NetworkManager profile keeps its reserved UUID.
   It is renamed to the new connection ID and pointed at the copied CA file,
   and the ownership manifest is updated.  The old connection ID is accepted
   only here, and only after the same ownership checks the app always applies.

Every step is idempotent, records completion in ``migration.json`` in the new
data directory, and runs only when an old data directory exists.  A step that
cannot finish safely is left for the next launch; nothing is guessed.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from .catalogue.store import atomic_write
from .config import (
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
    SECRET_PURPOSE,
    SECRET_SCHEMA_ATTRIBUTE_PURPOSE,
    SECRET_SCHEMA_ATTRIBUTE_USERNAME,
    SECRET_SCHEMA_NAME,
    certificate_dir,
    ensure_private_dir,
    user_data_dir,
)

log = logging.getLogger(__name__)

# Identifiers used by 0.1.x.  Do not use them anywhere else.
LEGACY_APP_SLUG = "solvetus-vpn"
LEGACY_CONNECTION_ID = "Solvetus VPN (managed)"
LEGACY_SECRET_SCHEMA = "org.solvetus.vpn"

STATE_NAME = "migration.json"
STATE_FORMAT = 1
MAX_COPY_BYTES = 16 * 1024 * 1024

DONE = "done"          # step completed (recorded; never runs again)
SKIPPED = "skipped"    # nothing to migrate (no old installation)
DEFERRED = "deferred"  # temporarily impossible (e.g. keyring locked); retry later
REFUSED = "refused"    # unsafe to proceed; left untouched, retried next launch

# Relative paths copied from the old data directory, and directories whose
# regular files are copied.
_FILES = ("settings.json", "ownership.json", "catalogue/last-known-good.zip",
          "catalogue/last-known-good.json")
_DIRECTORIES = ("certificates/nm-openvpn",)


@dataclass(frozen=True)
class StepResult:
    status: str
    detail: str = ""


# ----------------------------------------------------------------- state


def legacy_data_dir() -> Path:
    """The 0.1.x data directory, under the same XDG data home."""
    return user_data_dir().parent / LEGACY_APP_SLUG


def legacy_certificate_dir() -> Path:
    return legacy_data_dir() / "certificates" / "nm-openvpn"


def legacy_install_present() -> bool:
    path = legacy_data_dir()
    return path.is_dir() and not path.is_symlink()


class MigrationState:
    def __init__(self, path: Path | None = None):
        self.path = path or (user_data_dir() / STATE_NAME)
        self.steps: dict[str, str] = {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            value = {}
        steps = value.get("steps") if isinstance(value, dict) else None
        if isinstance(steps, dict):
            self.steps = {str(k): str(v) for k, v in steps.items()}

    def done(self, step: str) -> bool:
        return self.steps.get(step) == DONE

    def mark_done(self, step: str) -> None:
        self.steps[step] = DONE
        data = {"format": STATE_FORMAT, "steps": dict(sorted(self.steps.items()))}
        atomic_write(self.path, (json.dumps(data, indent=2) + "\n").encode("utf-8"))


# ----------------------------------------------------------------- files


def _regular_file(path: Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None  # symlinks, devices and directories are never followed
    return info


def _copy_file(source: Path, target: Path) -> str:
    """Copy one regular file privately.  Returns 'copied', 'kept' or 'skipped'."""
    if target.exists() or target.is_symlink():
        return "kept"
    info = _regular_file(source)
    if info is None or info.st_size > MAX_COPY_BYTES:
        return "skipped"
    # Open without following a symlink swapped in after the check above.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_COPY_BYTES + 1)
    if len(data) > MAX_COPY_BYTES:
        return "skipped"
    ensure_private_dir(target.parent)
    atomic_write(target, data, mode=0o600)
    return "copied"


def migrate_files(state: MigrationState | None = None) -> StepResult:
    if not legacy_install_present():
        return StepResult(SKIPPED)
    state = state or MigrationState()
    if state.done("files"):
        return StepResult(DONE)
    old, new = legacy_data_dir(), user_data_dir()
    ensure_private_dir(new)
    counts = {"copied": 0, "kept": 0, "skipped": 0}
    for relative in _FILES:
        counts[_copy_file(old / relative, new / relative)] += 1
    for relative in _DIRECTORIES:
        directory = old / relative
        if not directory.is_dir() or directory.is_symlink():
            continue
        ensure_private_dir(new / relative)
        ensure_private_dir((new / relative).parent)
        for entry in sorted(directory.iterdir()):
            counts[_copy_file(entry, new / relative / entry.name)] += 1
    state.mark_done("files")
    log.info(
        "migrated data from the previous release: %d copied, %d kept, %d skipped",
        counts["copied"], counts["kept"], counts["skipped"],
    )
    return StepResult(DONE)


# --------------------------------------------------------------- keyring


class KeyringError(RuntimeError):
    """The keyring is unavailable, locked or refused an operation."""


class KeyringBackend(Protocol):
    def legacy_entries(self) -> list[tuple[str, str]]:
        """Return (vpn_username, password) pairs stored under the old schema."""

    def lookup(self, username: str) -> str | None:
        """Look up a password under the new schema."""

    def store(self, username: str, password: str) -> None:
        """Store a password under the new schema."""

    def clear_legacy(self, username: str) -> None:
        """Delete the old-schema entry for *username*."""


class LibsecretBackend:
    """Secret Service access for the migration, via libsecret."""

    def __init__(self, legacy_schema: str = LEGACY_SECRET_SCHEMA, new_schema: str = SECRET_SCHEMA_NAME):
        import gi

        gi.require_version("Secret", "1")
        from gi.repository import GLib, Secret

        self._GLib = GLib
        self._Secret = Secret
        attributes = {
            SECRET_SCHEMA_ATTRIBUTE_USERNAME: Secret.SchemaAttributeType.STRING,
            SECRET_SCHEMA_ATTRIBUTE_PURPOSE: Secret.SchemaAttributeType.STRING,
        }
        self._legacy = Secret.Schema.new(legacy_schema, Secret.SchemaFlags.NONE, attributes)
        self._new = Secret.Schema.new(new_schema, Secret.SchemaFlags.NONE, attributes)

    @staticmethod
    def _attributes(username: str) -> dict[str, str]:
        return {
            SECRET_SCHEMA_ATTRIBUTE_USERNAME: username,
            SECRET_SCHEMA_ATTRIBUTE_PURPOSE: SECRET_PURPOSE,
        }

    def legacy_entries(self) -> list[tuple[str, str]]:
        Secret = self._Secret
        flags = Secret.SearchFlags.ALL | Secret.SearchFlags.UNLOCK | Secret.SearchFlags.LOAD_SECRETS
        try:
            items = Secret.password_search_sync(
                self._legacy, {SECRET_SCHEMA_ATTRIBUTE_PURPOSE: SECRET_PURPOSE}, flags, None
            )
        except self._GLib.Error as exc:
            raise KeyringError(exc.message) from exc
        entries = []
        for item in items or []:
            username = (item.get_attributes() or {}).get(SECRET_SCHEMA_ATTRIBUTE_USERNAME, "")
            try:
                value = item.retrieve_secret_sync(None)
            except self._GLib.Error as exc:
                raise KeyringError(exc.message) from exc
            if value is None:
                raise KeyringError("the keyring did not return a stored secret")
            entries.append((username, value.get_text() or ""))
        return entries

    def lookup(self, username: str) -> str | None:
        try:
            return self._Secret.password_lookup_sync(self._new, self._attributes(username), None)
        except self._GLib.Error as exc:
            raise KeyringError(exc.message) from exc

    def store(self, username: str, password: str) -> None:
        from .config import APP_NAME

        try:
            ok = self._Secret.password_store_sync(
                self._new,
                self._attributes(username),
                self._Secret.COLLECTION_DEFAULT,
                f"{APP_NAME} VPN password for {username}",
                password,
                None,
            )
        except self._GLib.Error as exc:
            raise KeyringError(exc.message) from exc
        if not ok:
            raise KeyringError("the keyring did not accept the password")

    def clear_legacy(self, username: str) -> None:
        try:
            self._Secret.password_clear_sync(self._legacy, self._attributes(username), None)
        except self._GLib.Error as exc:
            raise KeyringError(exc.message) from exc


def migrate_keyring(
    backend: KeyringBackend | None = None,
    state: MigrationState | None = None,
) -> StepResult:
    if not legacy_install_present():
        return StepResult(SKIPPED)
    state = state or MigrationState()
    if state.done("keyring"):
        return StepResult(DONE)
    try:
        backend = backend or LibsecretBackend()
        entries = backend.legacy_entries()
        moved = kept = 0
        for username, password in entries:
            if not username or not password:
                continue
            existing = backend.lookup(username)
            if existing is None:
                backend.store(username, password)
                if backend.lookup(username) != password:
                    raise KeyringError("the copied password could not be verified")
                moved += 1
            else:
                kept += 1  # a password saved with the new release wins
            backend.clear_legacy(username)
    except KeyringError as exc:
        log.warning("saved-password migration postponed: %s", exc)
        return StepResult(DEFERRED, str(exc))
    except Exception as exc:  # e.g. libsecret missing; never fatal
        log.warning("saved-password migration postponed: %s", type(exc).__name__)
        return StepResult(DEFERRED, type(exc).__name__)
    state.mark_done("keyring")
    log.info("migrated saved passwords: %d copied, %d already present", moved, kept)
    return StepResult(DONE)


# --------------------------------------------------------------- profile


def migrate_profile(
    connections,
    local_username: str,
    *,
    update: Callable | None = None,
    state: MigrationState | None = None,
) -> StepResult:
    """Adopt the 0.1.x managed profile: rename it and move its CA.

    *connections* is the NetworkManager connection list; *update* receives
    ``(connection, variant)`` and must persist the new settings (defaults to
    ``update_connection_sync``).
    """
    if not legacy_install_present():
        return StepResult(SKIPPED)
    state = state or MigrationState()
    if state.done("profile"):
        return StepResult(DONE)
    if not state.done("files"):
        return StepResult(DEFERRED, "the previous release's files have not been migrated yet")

    import gi

    gi.require_version("NM", "1.0")
    from gi.repository import NM

    from .nm.importer import ImportVerificationError, check_ca_file
    from .nm.profile import build_variant
    from .ownership import OwnershipEntry, OwnershipError, OwnershipStore, connection_is_owned

    try:
        store = OwnershipStore.load()
    except OwnershipError as exc:
        return StepResult(REFUSED, f"the previous ownership manifest is unreadable: {exc}")
    entry = store.get(MANAGED_UUID)
    if set(store.entries) - {MANAGED_UUID}:
        return StepResult(REFUSED, "the previous ownership manifest has unexpected entries")
    if entry is None:
        state.mark_done("profile")  # the previous release never created a profile
        return StepResult(DONE)
    if entry.connection_id not in {LEGACY_CONNECTION_ID, MANAGED_CONNECTION_ID}:
        return StepResult(REFUSED, "the previous ownership manifest uses an unknown connection ID")
    if entry.service_type != OPENVPN_SERVICE_TYPE or not entry.ca_sha256:
        return StepResult(REFUSED, "the previous ownership manifest is incomplete")

    candidates = []
    for connection in connections:
        if not isinstance(connection, NM.Connection):
            continue
        s_con = connection.get_setting_connection()
        if s_con is None:
            continue
        if s_con.get_uuid() == MANAGED_UUID or s_con.get_id() in {LEGACY_CONNECTION_ID, MANAGED_CONNECTION_ID}:
            candidates.append(connection)

    new_ca = certificate_dir() / Path(entry.ca_path or "").name

    if not candidates:
        # The profile was deleted; keep the manifest consistent for the new
        # release, which will treat it as stale and rebuild the profile.
        store.record(_entry_for(entry, new_ca, OwnershipEntry))
        state.mark_done("profile")
        return StepResult(DONE)
    if len(candidates) > 1:
        return StepResult(REFUSED, "more than one connection uses the reserved ID or UUID")

    connection = candidates[0]
    s_con = connection.get_setting_connection()
    s_vpn = connection.get_setting_vpn()
    current_id = s_con.get_id()
    if current_id not in {LEGACY_CONNECTION_ID, MANAGED_CONNECTION_ID} or s_vpn is None:
        return StepResult(REFUSED, "the reserved profile has an unexpected ID")
    # The same ownership rules as always, with the ID the profile has now.
    check = OwnershipEntry(uuid=MANAGED_UUID, connection_id=current_id, service_type=entry.service_type)
    if not connection_is_owned(connection, check, local_username):
        return StepResult(REFUSED, "the reserved profile is not restricted to the current user")

    if not entry.ca_path or Path(entry.ca_path).parent not in {legacy_certificate_dir(), certificate_dir()}:
        return StepResult(REFUSED, "the previous CA file is outside the application directory")
    try:
        check_ca_file(str(new_ca), certificate_dir(), entry.ca_sha256)
    except ImportVerificationError as exc:
        return StepResult(REFUSED, f"the copied CA file failed verification: {exc}")

    profile_ca = s_vpn.get_data_item("ca")
    if current_id != MANAGED_CONNECTION_ID or profile_ca != str(new_ca):
        if profile_ca not in {entry.ca_path, str(new_ca)}:
            return StepResult(REFUSED, "the profile CA does not match the ownership manifest")
        updated = NM.SimpleConnection.new_clone(connection)
        updated.get_setting_connection().props.id = MANAGED_CONNECTION_ID
        updated.get_setting_vpn().add_data_item("ca", str(new_ca))
        try:
            updated.verify()
            variant = build_variant(updated)
            if update is None:
                from .nm.client import update_connection_sync

                update_connection_sync(connection, variant)
                _wait_for_cache(lambda: connection.get_id() == MANAGED_CONNECTION_ID)
            else:
                update(connection, variant)
        except Exception as exc:
            return StepResult(REFUSED, f"NetworkManager did not accept the renamed profile: {exc}")

    store.record(_entry_for(entry, new_ca, OwnershipEntry))
    state.mark_done("profile")
    log.info("adopted the managed NetworkManager profile from the previous release")
    return StepResult(DONE)


def _wait_for_cache(condition: Callable[[], bool], timeout: float = 3.0) -> None:
    """Let libnm's connection cache catch up with an update we just made."""
    import time

    from gi.repository import GLib

    context = GLib.MainContext.default()
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        if not context.iteration(False):
            time.sleep(0.02)


def _entry_for(entry, new_ca: Path, entry_type):
    return entry_type(
        uuid=MANAGED_UUID,
        connection_id=MANAGED_CONNECTION_ID,
        service_type=entry.service_type,
        created_at=entry.created_at,
        source_sha256=entry.source_sha256,
        ca_sha256=entry.ca_sha256,
        ca_path=str(new_ca) if entry.ca_path else "",
    )


# --------------------------------------------------------------- drivers


def migrate_user_data() -> None:
    """Files and keyring; run before any settings are loaded."""
    if not legacy_install_present():
        return
    try:
        migrate_files()
    except Exception:
        log.exception("could not migrate data from the previous release")
        return
    migrate_keyring()
