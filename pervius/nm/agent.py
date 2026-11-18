"""System-bus NetworkManager SecretAgent.

NetworkManager 1.58 stores the bus connection and unique name on which
AgentManager.RegisterWithCapabilities() was called, and later calls
GetSecrets() back on that same connection.  libnm defaults to the system bus
(LIBNM_USE_SESSION_BUS is a test-only override), so this agent registers on
the system bus directly with Gio rather than relying on NM.SecretAgentOld.

The agent is intentionally narrow:
  * only root (NetworkManager) callers are accepted;
  * only the app-owned UUID/ID/service type in the local manifest;
  * only the current user's permission;
  * only the "vpn" setting and the OpenVPN password key.
"""

from __future__ import annotations

import logging
import os
import pwd
from typing import Callable

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from ..config import (  # noqa: E402
    AGENT_MANAGER_INTERFACE,
    AGENT_MANAGER_PATH,
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
    SECRET_AGENT_IDENTIFIER,
    SECRET_AGENT_INTERFACE,
    SECRET_AGENT_PATH,
)
from ..ownership import (  # noqa: E402
    OwnershipEntry,
    OwnershipStore,
    permissions_are_restricted_to_user,
)

log = logging.getLogger(__name__)

NOT_AUTHORIZED = SECRET_AGENT_INTERFACE + ".NotAuthorized"
NO_SECRETS = SECRET_AGENT_INTERFACE + ".NoSecrets"

_SECRET_AGENT_XML = """
<node>
  <interface name="org.freedesktop.NetworkManager.SecretAgent">
    <method name="GetSecrets">
      <arg type="a{sa{sv}}" name="connection" direction="in"/>
      <arg type="o" name="connection_path" direction="in"/>
      <arg type="s" name="setting_name" direction="in"/>
      <arg type="as" name="hints" direction="in"/>
      <arg type="u" name="flags" direction="in"/>
      <arg type="a{sa{sv}}" name="secrets" direction="out"/>
    </method>
    <method name="CancelGetSecrets">
      <arg type="o" name="connection_path" direction="in"/>
      <arg type="s" name="setting_name" direction="in"/>
    </method>
    <method name="SaveSecrets">
      <arg type="a{sa{sv}}" name="connection" direction="in"/>
      <arg type="o" name="connection_path" direction="in"/>
    </method>
    <method name="DeleteSecrets">
      <arg type="a{sa{sv}}" name="connection" direction="in"/>
      <arg type="o" name="connection_path" direction="in"/>
    </method>
  </interface>
</node>
"""


class AgentError(RuntimeError):
    def __init__(self, dbus_name: str, message: str):
        self.dbus_name = dbus_name
        super().__init__(message)


def _current_username() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def _unpack_connection_hash(value: dict, username: str) -> tuple[str, str, str]:
    """Extract and validate the fields we rely on from NM's hash."""
    connection = value.get("connection")
    vpn = value.get("vpn")
    if not isinstance(connection, dict) or not isinstance(vpn, dict):
        raise AgentError(NOT_AUTHORIZED, "connection description is malformed")
    uuid_value = connection.get("uuid")
    id_value = connection.get("id")
    service_value = vpn.get("service-type")
    permissions_value = connection.get("permissions")
    try:
        uuid = uuid_value.get_string() if isinstance(uuid_value, GLib.Variant) else str(uuid_value)
        connection_id = id_value.get_string() if isinstance(id_value, GLib.Variant) else str(id_value)
        service = (
            service_value.get_string()
            if isinstance(service_value, GLib.Variant)
            else str(service_value)
        )
        permissions = permissions_value.unpack() if isinstance(permissions_value, GLib.Variant) else permissions_value
    except Exception as exc:
        raise AgentError(NOT_AUTHORIZED, "connection description is malformed") from exc
    if not isinstance(permissions, (list, tuple)):
        permissions = []
    if uuid != MANAGED_UUID:
        raise AgentError(NOT_AUTHORIZED, "connection UUID is not managed by this application")
    if connection_id != MANAGED_CONNECTION_ID:
        raise AgentError(NOT_AUTHORIZED, "connection ID is not managed by this application")
    if service != OPENVPN_SERVICE_TYPE:
        raise AgentError(NOT_AUTHORIZED, "connection is not an OpenVPN profile")
    if not permissions_are_restricted_to_user(permissions, username):
        raise AgentError(NOT_AUTHORIZED, "connection is not restricted to the current user")
    return uuid, connection_id, service


def ownership_matches(entry: OwnershipEntry | None) -> bool:
    return bool(
        entry
        and entry.uuid == MANAGED_UUID
        and entry.connection_id == MANAGED_CONNECTION_ID
        and entry.service_type == OPENVPN_SERVICE_TYPE
    )


class NetworkManagerSecretAgent:
    """Serve the VPN password to NetworkManager, and to nothing else.

    ``credentials`` is the password store and ``vpn_username_provider``
    returns the VPN account name to look up.  This class is the only place
    that reads a stored password; it does so only inside GetSecrets, after
    the caller and the connection have been authorized.
    """

    def __init__(
        self,
        credentials,
        vpn_username_provider: Callable[[], str],
        *,
        username: str | None = None,
        store_provider: Callable[[], OwnershipStore] | None = None,
    ):
        self._credentials = credentials
        self._vpn_username_provider = vpn_username_provider
        self._username = username or _current_username()
        self._store_provider = store_provider or (lambda: OwnershipStore.load())
        self._bus: Gio.DBusConnection | None = None
        self._registration_id: int | None = None
        self._name_subscription: int | None = None
        self._registered = False
        self._node_info = Gio.DBusNodeInfo.new_for_xml(_SECRET_AGENT_XML)

    @property
    def registered(self) -> bool:
        return self._registered

    def register(self) -> None:
        if self._bus is None:
            try:
                self._bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            except GLib.Error as exc:
                raise AgentError(NOT_AUTHORIZED, f"could not connect to the system bus: {exc.message}") from exc
        if self._registration_id is None:
            interface = self._node_info.interfaces[0]
            try:
                self._registration_id = self._bus.register_object(
                    SECRET_AGENT_PATH,
                    interface,
                    self._on_method_call,
                    None,
                    None,
                )
            except GLib.Error as exc:
                raise AgentError(NOT_AUTHORIZED, f"could not export the secret agent: {exc.message}") from exc
        self._register_with_manager()
        if self._name_subscription is None:
            self._name_subscription = self._bus.signal_subscribe(
                "org.freedesktop.DBus",
                "org.freedesktop.DBus",
                "NameOwnerChanged",
                "/org/freedesktop/DBus",
                "org.freedesktop.NetworkManager",
                Gio.DBusSignalFlags.NONE,
                self._on_name_owner_changed,
            )

    def _register_with_manager(self) -> None:
        if self._bus is None:
            return
        try:
            self._bus.call_sync(
                "org.freedesktop.NetworkManager",
                AGENT_MANAGER_PATH,
                AGENT_MANAGER_INTERFACE,
                "RegisterWithCapabilities",
                GLib.Variant("(su)", (SECRET_AGENT_IDENTIFIER, 0)),
                None,
                Gio.DBusCallFlags.NONE,
                10000,
                None,
            )
        except GLib.Error as exc:
            self._registered = False
            raise AgentError(
                NOT_AUTHORIZED,
                "could not register the NetworkManager secret agent "
                f"(is another instance already running?): {exc.message}",
            ) from exc
        self._registered = True

    def unregister(self) -> None:
        if self._bus is not None and self._registered:
            try:
                self._bus.call_sync(
                    "org.freedesktop.NetworkManager",
                    AGENT_MANAGER_PATH,
                    AGENT_MANAGER_INTERFACE,
                    "Unregister",
                    None,
                    None,
                    Gio.DBusCallFlags.NONE,
                    5000,
                    None,
                )
            except GLib.Error as exc:
                log.info("secret agent unregister failed: %s", exc.message)
        self._registered = False
        if self._bus is not None and self._name_subscription is not None:
            self._bus.signal_unsubscribe(self._name_subscription)
            self._name_subscription = None

    def _on_name_owner_changed(self, _bus, _sender, _path, _interface, _signal, params, *_args) -> None:
        try:
            _name, old_owner, new_owner = params.unpack()
        except Exception:
            return
        if new_owner and not old_owner:
            try:
                self._register_with_manager()
                log.info("re-registered secret agent after NetworkManager restarted")
            except AgentError as exc:
                log.warning("could not re-register secret agent: %s", exc)

    def _sender_is_root(self, sender: str | None) -> bool:
        if not sender or self._bus is None:
            return False
        try:
            reply = self._bus.call_sync(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixUser",
                GLib.Variant("(s)", (sender,)),
                GLib.VariantType.new("(u)"),
                Gio.DBusCallFlags.NONE,
                5000,
                None,
            )
            uid = reply.unpack()[0]
        except (GLib.Error, TypeError, IndexError):
            return False
        return uid == 0

    def _manifest_entry(self) -> OwnershipEntry | None:
        try:
            store = self._store_provider()
            return store.get(MANAGED_UUID)
        except Exception as exc:
            # A manifest read failure must not turn into permission to release
            # secrets.
            log.warning("could not read ownership manifest in secret agent: %s", exc)
            return None

    def _lookup_password(self) -> str | None:
        try:
            vpn_username = (self._vpn_username_provider() or "").strip()
        except Exception:
            return None
        if not vpn_username:
            return None
        return self._credentials.lookup(vpn_username)

    def _on_method_call(
        self,
        _connection,
        sender,
        _object_path,
        _interface_name,
        method_name,
        parameters,
        invocation,
    ):
        if not self._sender_is_root(sender):
            invocation.return_dbus_error(NOT_AUTHORIZED, "only NetworkManager may request secrets")
            return None

        if method_name == "GetSecrets":
            try:
                connection_hash, _path, setting_name, _hints, _flags = parameters.unpack()
                if setting_name != "vpn":
                    raise AgentError(NO_SECRETS, "no secrets for this setting")
                _unpack_connection_hash(connection_hash, self._username)
                if not ownership_matches(self._manifest_entry()):
                    raise AgentError(NOT_AUTHORIZED, "connection is not in the ownership manifest")
                password = self._lookup_password()
                if not password:
                    raise AgentError(NO_SECRETS, "no password is available")
                secrets = {"vpn": {"password": GLib.Variant("s", password)}}
                invocation.return_value(GLib.Variant("(a{sa{sv}})", (secrets,)))
            except AgentError as exc:
                invocation.return_dbus_error(exc.dbus_name, str(exc))
            except Exception:
                log.exception("unexpected error while serving a secret request")
                invocation.return_dbus_error(NO_SECRETS, "could not provide secrets")
            return None

        if method_name in {"SaveSecrets", "DeleteSecrets"}:
            # AGENT_OWNED secrets are stored by this application, not by NM.
            # Nothing to save.  DeleteSecrets is deliberately a no-op: deleting
            # an NM profile must not silently erase the user's saved password.
            invocation.return_value(None)
            return None

        if method_name == "CancelGetSecrets":
            invocation.return_value(None)
            return None

        invocation.return_dbus_error(
            "org.freedesktop.DBus.Error.UnknownMethod",
            f"unknown secret agent method {method_name}",
        )
        return None
