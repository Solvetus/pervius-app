"""Ownership manifest and fail-closed ownership checks.

A UUID alone is not proof of ownership: users can copy keyfiles or create a
connection with a guessed ID.  A connection is ours only when the manifest
entry, reserved ID, UUID, connection/service types and user permission all
match.  Anything ambiguous stops the operation.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from .config import (  # noqa: E402
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
    ownership_manifest_path,
)
from .catalogue.models import utc_now_iso  # noqa: E402
from .catalogue.store import atomic_write  # noqa: E402

log = logging.getLogger(__name__)


class OwnershipError(RuntimeError):
    pass


@dataclass
class OwnershipEntry:
    uuid: str = MANAGED_UUID
    connection_id: str = MANAGED_CONNECTION_ID
    service_type: str = OPENVPN_SERVICE_TYPE
    created_at: str = ""
    updated_at: str = ""
    source_sha256: str = ""
    ca_sha256: str = ""
    ca_path: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class OwnershipStore:
    path: Path | None = None
    version: int = 1
    entries: dict[str, OwnershipEntry] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.path = self.path or ownership_manifest_path()

    @classmethod
    def load(cls, path: Path | None = None) -> "OwnershipStore":
        store = cls(path=path)
        try:
            raw = store.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return store
        except OSError as exc:
            raise OwnershipError(f"could not read ownership manifest: {exc}") from exc
        try:
            value = json.loads(raw)
        except ValueError as exc:
            raise OwnershipError(f"ownership manifest is not valid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise OwnershipError("ownership manifest has an unexpected shape")
        entries = value.get("profiles")
        if not isinstance(entries, dict):
            raise OwnershipError("ownership manifest is missing its profiles map")
        for uuid, item in entries.items():
            if not isinstance(uuid, str) or not isinstance(item, dict):
                raise OwnershipError("ownership manifest contains a malformed entry")
            entry = OwnershipEntry(
                uuid=uuid,
                connection_id=str(item.get("connection_id") or ""),
                service_type=str(item.get("service_type") or ""),
                created_at=str(item.get("created_at") or ""),
                updated_at=str(item.get("updated_at") or ""),
                source_sha256=str(item.get("source_sha256") or ""),
                ca_sha256=str(item.get("ca_sha256") or ""),
                ca_path=str(item.get("ca_path") or ""),
            )
            store.entries[uuid] = entry
        return store

    def save(self) -> None:
        data = {
            "format": self.version,
            "profiles": {uuid: entry.as_dict() for uuid, entry in sorted(self.entries.items())},
        }
        atomic_write(
            self.path,
            (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    def get(self, uuid: str = MANAGED_UUID) -> OwnershipEntry | None:
        return self.entries.get(uuid)

    def record(self, entry: OwnershipEntry) -> None:
        if not entry.created_at:
            entry.created_at = utc_now_iso()
        entry.updated_at = utc_now_iso()
        self.entries[entry.uuid] = entry
        self.save()

    def remove(self, uuid: str = MANAGED_UUID) -> None:
        self.entries.pop(uuid, None)
        self.save()


def _connection_setting(connection: NM.Connection) -> NM.SettingConnection | None:
    setting = connection.get_setting_connection()
    return setting if isinstance(setting, NM.SettingConnection) else None


def _vpn_setting(connection: NM.Connection) -> NM.SettingVpn | None:
    setting = connection.get_setting_vpn()
    return setting if isinstance(setting, NM.SettingVpn) else None


def permissions_are_restricted_to_user(permissions: Iterable[str] | None, username: str) -> bool:
    """Return True only for exactly one user permission for *username*.

    libnm serializes a permission without a detail as ``user:name:``.  An empty
    permissions list means "all users", so it must never be treated as an
    ownership match.
    """
    if not username or permissions is None:
        return False
    items = list(permissions)
    if len(items) != 1:
        return False
    parts = items[0].split(":", 2)
    if len(parts) < 2:
        return False
    ptype, pitem = parts[0], parts[1]
    detail = parts[2] if len(parts) == 3 else ""
    return ptype == "user" and pitem == username and detail == ""


def connection_is_owned(
    connection: NM.Connection,
    entry: OwnershipEntry,
    username: str,
) -> bool:
    if not username:
        return False
    s_con = _connection_setting(connection)
    s_vpn = _vpn_setting(connection)
    if s_con is None or s_vpn is None:
        return False
    try:
        if connection.get_connection_type() != "vpn":
            return False
    except Exception:
        return False
    if s_con.get_uuid() != entry.uuid:
        return False
    if s_con.get_id() != entry.connection_id:
        return False
    if s_vpn.get_service_type() != entry.service_type:
        return False
    try:
        permissions = list(s_con.props.permissions or [])
    except Exception:
        return False
    if not permissions_are_restricted_to_user(permissions, username):
        return False
    try:
        if not s_con.permissions_user_allowed(username):
            return False
    except Exception:
        return False
    return True


@dataclass
class ManagedLookup:
    connection: NM.Connection | None
    entry: OwnershipEntry | None
    stale_entry: bool = False


def _connections(connections: Iterable[NM.Connection]) -> list[NM.Connection]:
    return [connection for connection in connections if isinstance(connection, NM.Connection)]


def find_managed_connection(
    connections: Iterable[NM.Connection],
    store: OwnershipStore,
    username: str,
) -> ManagedLookup:
    """Find our managed connection, or stop on ambiguity."""
    all_connections = _connections(connections)
    entry = store.get()
    matches: list[NM.Connection] = []

    if set(store.entries) - {MANAGED_UUID}:
        raise OwnershipError(
            "ownership manifest contains entries other than the reserved managed profile"
        )

    for connection in all_connections:
        s_con = _connection_setting(connection)
        if s_con is None:
            continue
        same_id = s_con.get_id() == MANAGED_CONNECTION_ID
        same_uuid = s_con.get_uuid() == MANAGED_UUID
        if same_id or same_uuid:
            matches.append(connection)

    if entry is None:
        if matches:
            raise OwnershipError(
                "a connection using the reserved Pervius ID or UUID already exists, "
                "but the ownership manifest has no matching entry; refusing to touch it"
            )
        return ManagedLookup(connection=None, entry=None)

    if entry.uuid != MANAGED_UUID or entry.connection_id != MANAGED_CONNECTION_ID:
        raise OwnershipError("ownership manifest entry does not use the reserved ID and UUID")

    if not matches:
        # A stale manifest is not permission to overwrite something else.  The
        # caller may create a new profile only after the collision check above.
        return ManagedLookup(connection=None, entry=entry, stale_entry=True)

    if len(matches) > 1:
        raise OwnershipError(
            "multiple connections use the reserved Pervius ID or UUID; refusing to choose"
        )

    connection = matches[0]
    if not connection_is_owned(connection, entry, username):
        raise OwnershipError(
            "the connection with the reserved Pervius ID/UUID does not match the "
            "ownership manifest or is not restricted to the current user; refusing to modify it"
        )
    return ManagedLookup(connection=connection, entry=entry)


def check_create_collision(
    connections: Iterable[NM.Connection],
    username: str,
) -> None:
    """Validate that a new managed profile can be created safely."""
    for connection in _connections(connections):
        s_con = _connection_setting(connection)
        if s_con is None:
            continue
        if s_con.get_id() == MANAGED_CONNECTION_ID or s_con.get_uuid() == MANAGED_UUID:
            raise OwnershipError(
                "the reserved Pervius connection ID or UUID is already in use by "
                "an unowned connection; refusing to overwrite it"
            )
