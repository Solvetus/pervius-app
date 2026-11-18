"""NetworkManager client helpers and activation wrappers."""

from __future__ import annotations

import logging
import threading
from typing import Callable

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

from ..config import MANAGED_UUID  # noqa: E402
from ..catalogue.models import ProfileRef  # noqa: E402
from .importer import import_and_prepare  # noqa: E402
from .profile import GuardOptions, PreparedProfile  # noqa: E402

log = logging.getLogger(__name__)


class NetworkManagerError(RuntimeError):
    pass


def new_client() -> NM.Client:
    try:
        client = NM.Client.new(None)
    except GLib.Error as exc:
        raise NetworkManagerError(f"could not connect to NetworkManager: {exc.message}") from exc
    if client is None:
        raise NetworkManagerError("could not create the NetworkManager client")
    if not client.get_nm_running():
        raise NetworkManagerError("NetworkManager is not running")
    return client


def get_connection_by_uuid(client: NM.Client, uuid: str = MANAGED_UUID) -> NM.Connection | None:
    try:
        connection = client.get_connection_by_uuid(uuid)
    except Exception:
        connection = None
    if connection is not None:
        return connection
    for candidate in client.get_connections():
        if candidate.get_uuid() == uuid:
            return candidate
    return None


def active_vpn_for_uuid(client: NM.Client, uuid: str = MANAGED_UUID) -> NM.VpnConnection | None:
    try:
        active_connections = client.get_active_connections()
    except Exception:
        return None
    for active in active_connections:
        if not isinstance(active, NM.VpnConnection):
            continue
        try:
            if active.get_uuid() == uuid:
                return active
        except Exception:
            continue
    return None


def vpn_state_name(active: NM.VpnConnection | None) -> str:
    if active is None:
        return "disconnected"
    try:
        state = active.get_vpn_state()
    except Exception:
        return "unknown"
    mapping = {
        int(NM.VpnConnectionState.UNKNOWN): "unknown",
        int(NM.VpnConnectionState.PREPARE): "prepare",
        int(NM.VpnConnectionState.NEED_AUTH): "need-auth",
        int(NM.VpnConnectionState.CONNECT): "connect",
        int(NM.VpnConnectionState.IP_CONFIG_GET): "ip-config",
        int(NM.VpnConnectionState.ACTIVATED): "activated",
        int(NM.VpnConnectionState.FAILED): "failed",
        int(NM.VpnConnectionState.DISCONNECTED): "disconnected",
    }
    return mapping.get(state, f"state-{state}")


def vpn_state_reason(active: NM.VpnConnection | None) -> str:
    if active is None:
        return ""
    try:
        reason = active.get_state_reason()
    except Exception:
        return ""
    try:
        return NM.VpnConnectionStateReason(reason).value_nick
    except Exception:
        return str(reason)


def prepare_managed_profile(
    ref: ProfileRef,
    vpn_username: str,
    local_username: str,
    guard: GuardOptions | None = None,
) -> PreparedProfile:
    """Import + verify in a worker thread; does not mutate the managed profile."""
    profile = ref.profile
    client = new_client()
    return import_and_prepare(
        client,
        profile.raw,
        profile,
        vpn_username=vpn_username,
        local_username=local_username,
        guard=guard,
    )


def prepare_managed_profile_async(
    ref: ProfileRef,
    vpn_username: str,
    local_username: str,
    callback: Callable[[PreparedProfile | None, Exception | None], None],
    guard: GuardOptions | None = None,
) -> threading.Thread:
    """Run prepare_managed_profile in a worker and deliver on the GLib loop."""

    def deliver(result, error) -> bool:
        callback(result, error)
        return False

    def worker() -> None:
        try:
            result = prepare_managed_profile(ref, vpn_username, local_username, guard)
        except Exception as exc:  # surfaced to the UI with a clear message
            log.warning("profile preparation failed: %s", exc)
            GLib.idle_add(deliver, None, exc)
        else:
            GLib.idle_add(deliver, result, None)

    thread = threading.Thread(target=worker, name="pervius-import", daemon=True)
    thread.start()
    return thread


def add_connection_async(
    client: NM.Client,
    variant: GLib.Variant,
    callback: Callable[[NM.RemoteConnection | None, Exception | None], None],
) -> None:
    def done(source, result, _user_data=None):
        try:
            connection, _out = source.add_connection2_finish(result)
        except GLib.Error as exc:
            callback(None, NetworkManagerError(f"could not create the managed profile: {exc.message}"))
        except Exception as exc:
            callback(None, exc)
        else:
            callback(connection, None)

    try:
        client.add_connection2(
            variant,
            NM.SettingsAddConnection2Flags.TO_DISK,
            None,
            False,
            None,
            done,
        )
    except Exception as exc:
        callback(None, exc)


def update_connection_async(
    connection: NM.RemoteConnection,
    variant: GLib.Variant,
    callback: Callable[[NM.RemoteConnection | None, Exception | None], None],
) -> None:
    def done(source, result, _user_data=None):
        try:
            source.update2_finish(result)
        except GLib.Error as exc:
            callback(None, NetworkManagerError(f"could not update the managed profile: {exc.message}"))
        except Exception as exc:
            callback(None, exc)
        else:
            callback(connection, None)

    try:
        connection.update2(
            variant,
            NM.SettingsUpdate2Flags.TO_DISK,
            None,
            None,
            done,
        )
    except Exception as exc:
        callback(None, exc)


def activate_async(
    client: NM.Client,
    connection: NM.Connection,
    callback: Callable[[NM.ActiveConnection | None, Exception | None], None],
) -> None:
    def done(source, result, _user_data=None):
        try:
            active = source.activate_connection_finish(result)
        except GLib.Error as exc:
            callback(None, NetworkManagerError(f"could not activate the VPN: {exc.message}"))
        except Exception as exc:
            callback(None, exc)
        else:
            callback(active, None)

    try:
        client.activate_connection_async(connection, None, None, None, done)
    except Exception as exc:
        callback(None, exc)


def deactivate_async(
    client: NM.Client,
    active: NM.ActiveConnection,
    callback: Callable[[bool, Exception | None], None],
) -> None:
    def done(source, result, _user_data=None):
        try:
            source.deactivate_connection_finish(result)
        except GLib.Error as exc:
            callback(False, NetworkManagerError(f"could not disconnect: {exc.message}"))
        except Exception as exc:
            callback(False, exc)
        else:
            callback(True, None)

    try:
        client.deactivate_connection_async(active, None, done)
    except Exception as exc:
        callback(False, exc)


# Synchronous helpers for the proof/diagnostic CLI.  The GUI uses the async
# variants so its main loop stays responsive.


def _run_loop(starter: Callable[[Callable], None]):
    loop = GLib.MainLoop()
    outcome: dict = {}

    def finish(value, error):
        outcome["value"] = value
        outcome["error"] = error
        loop.quit()

    starter(finish)
    loop.run()
    if outcome.get("error"):
        raise outcome["error"]
    return outcome.get("value")


def add_connection_sync(client: NM.Client, variant: GLib.Variant) -> NM.RemoteConnection:
    return _run_loop(lambda done: add_connection_async(client, variant, done))


def update_connection_sync(connection: NM.RemoteConnection, variant: GLib.Variant) -> NM.RemoteConnection:
    return _run_loop(lambda done: update_connection_async(connection, variant, done))


def activate_sync(client: NM.Client, connection: NM.Connection) -> NM.ActiveConnection:
    return _run_loop(lambda done: activate_async(client, connection, done))


def deactivate_sync(client: NM.Client, active: NM.ActiveConnection) -> bool:
    return _run_loop(lambda done: deactivate_async(client, active, done))


def delete_sync(connection: NM.Connection) -> bool:
    try:
        return bool(connection.delete(None))
    except GLib.Error as exc:
        raise NetworkManagerError(f"could not delete the NetworkManager profile: {exc.message}") from exc
