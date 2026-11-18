"""NetworkManager client helpers and activation wrappers."""

from __future__ import annotations

import logging
import threading
from typing import Callable

import gi

gi.require_version("NM", "1.0")
from gi.repository import Gio, GLib, NM  # noqa: E402

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


# Every NetworkManager call from the GUI is bounded: a timed-out call is
# cancelled and reported as an error instead of leaving the app waiting.
NM_CALL_TIMEOUT = 20
NM_ACTIVATE_TIMEOUT = 30


class _Once:
    """Deliver a callback exactly once (completion or timeout, whichever first)."""

    def __init__(self, callback, seconds: int, what: str):
        self._callback = callback
        self._done = False
        self.cancellable = Gio.Cancellable()
        self._what = what
        self._timer = GLib.timeout_add_seconds(seconds, self._expire)

    def _expire(self):
        self._timer = None
        if not self._done:
            self.cancellable.cancel()
            self.deliver(None, NetworkManagerError(f"{self._what} timed out"))
        return False

    def deliver(self, value, error):
        if self._done:
            return
        self._done = True
        if self._timer is not None:
            GLib.source_remove(self._timer)
            self._timer = None
        self._callback(value, error)


def add_connection_async(
    client: NM.Client,
    variant: GLib.Variant,
    callback: Callable[[NM.RemoteConnection | None, Exception | None], None],
) -> None:
    once = _Once(callback, NM_CALL_TIMEOUT, "creating the managed profile")

    def done(source, result, _user_data=None):
        try:
            connection, _out = source.add_connection2_finish(result)
        except GLib.Error as exc:
            once.deliver(None, NetworkManagerError(f"could not create the managed profile: {exc.message}"))
        except Exception as exc:
            once.deliver(None, exc)
        else:
            once.deliver(connection, None)

    try:
        client.add_connection2(
            variant,
            NM.SettingsAddConnection2Flags.TO_DISK,
            None,
            False,
            once.cancellable,
            done,
        )
    except Exception as exc:
        once.deliver(None, exc)


def update_connection_async(
    connection: NM.RemoteConnection,
    variant: GLib.Variant,
    callback: Callable[[NM.RemoteConnection | None, Exception | None], None],
) -> None:
    once = _Once(callback, NM_CALL_TIMEOUT, "updating the managed profile")

    def done(source, result, _user_data=None):
        try:
            source.update2_finish(result)
        except GLib.Error as exc:
            once.deliver(None, NetworkManagerError(f"could not update the managed profile: {exc.message}"))
        except Exception as exc:
            once.deliver(None, exc)
        else:
            once.deliver(connection, None)

    try:
        connection.update2(
            variant,
            NM.SettingsUpdate2Flags.TO_DISK,
            None,
            once.cancellable,
            done,
        )
    except Exception as exc:
        once.deliver(None, exc)


def activate_async(
    client: NM.Client,
    connection: NM.Connection,
    callback: Callable[[NM.ActiveConnection | None, Exception | None], None],
) -> Gio.Cancellable:
    """Start activation; returns a cancellable that aborts the request."""
    once = _Once(callback, NM_ACTIVATE_TIMEOUT, "starting the VPN")

    def done(source, result, _user_data=None):
        try:
            active = source.activate_connection_finish(result)
        except GLib.Error as exc:
            once.deliver(None, NetworkManagerError(f"could not activate the VPN: {exc.message}"))
        except Exception as exc:
            once.deliver(None, exc)
        else:
            once.deliver(active, None)

    try:
        client.activate_connection_async(connection, None, None, once.cancellable, done)
    except Exception as exc:
        once.deliver(None, exc)
    return once.cancellable


def deactivate_async(
    client: NM.Client,
    active: NM.ActiveConnection,
    callback: Callable[[bool, Exception | None], None],
) -> None:
    once = _Once(lambda value, error: callback(bool(value), error), NM_CALL_TIMEOUT, "disconnecting")

    def done(source, result, _user_data=None):
        try:
            source.deactivate_connection_finish(result)
        except GLib.Error as exc:
            once.deliver(False, NetworkManagerError(f"could not disconnect: {exc.message}"))
        except Exception as exc:
            once.deliver(False, exc)
        else:
            once.deliver(True, None)

    try:
        client.deactivate_connection_async(active, once.cancellable, done)
    except Exception as exc:
        once.deliver(False, exc)


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
