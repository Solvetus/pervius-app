"""Pervius kill-switch system service.

Runs as root under systemd.  It owns exactly one nftables table, never flushes
the global ruleset, and never invokes a shell.  The public D-Bus surface is
limited to protecting the reserved app-owned profile: arming, reconfiguring
the allowed interfaces, swapping the VPN server endpoints atomically, and
disarming.  Callers never supply rule text, paths or addresses; endpoints
always come from the profile, resolved by the service itself.
"""

from __future__ import annotations

import json
import logging
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gio", "2.0")
gi.require_version("NM", "1.0")
from gi.repository import Gio, GLib, NM  # noqa: E402

from ..config import (  # noqa: E402
    GUARD_OPTIONS_PATH,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
    TUNNEL_INTERFACE,
)
from .profile import ProfileError, remotes_from_profile_data  # noqa: E402
from .rules import (  # noqa: E402
    GUARD_TABLE_SPEC,
    LEGACY_GUARD_TABLE_SPEC,
    MAX_ENDPOINTS,
    TABLE_SPEC,
    Endpoint,
    Resolution,
    RulesError,
    build_dns_window,
    build_dns_window_close,
    build_endpoint_swap,
    build_ruleset,
    cgroup_match,
    endpoints_from_state,
    resolve_remotes,
    resolver_addresses,
    validate_interfaces,
)

log = logging.getLogger(__name__)

BUS_NAME = "com.solvetus.Pervius.KillSwitch1"
OBJECT_PATH = "/com/solvetus/Pervius/KillSwitch1"
INTERFACE = "com.solvetus.Pervius.KillSwitch1"
POLKIT_ACTION = "com.solvetus.pervius.killswitch.control"
STATE_DIR = Path("/run/pervius")
STATE_FILE = STATE_DIR / "killswitch.json"
STATE_VERSION = 2
NFT_TIMEOUT = 20
# At most one DNS window per this many seconds.
DNS_WINDOW_INTERVAL = 30.0
CGROUP_ROOT = Path("/sys/fs/cgroup")
GUARD_HOOK = "/usr/lib/NetworkManager/dispatcher.d/90-pervius-guard"

PERMISSION_DENIED = f"{INTERFACE}.PermissionDenied"
OPERATION_FAILED = f"{INTERFACE}.Failed"
NOT_AVAILABLE = f"{INTERFACE}.NotAvailable"
NOT_ARMED = f"{INTERFACE}.NotArmed"
RESOLVE_FAILED = f"{INTERFACE}.ResolveFailed"

_INTROSPECTION_XML = """
<node>
  <interface name="@INTERFACE@">
    <method name="Arm">
      <arg name="uuid" type="s" direction="in"/>
      <arg name="allow_lan" type="b" direction="in"/>
      <arg name="interfaces" type="as" direction="in"/>
      <arg name="status" type="a{sv}" direction="out"/>
    </method>
    <method name="Configure">
      <arg name="allow_lan" type="b" direction="in"/>
      <arg name="interfaces" type="as" direction="in"/>
      <arg name="status" type="a{sv}" direction="out"/>
    </method>
    <method name="UpdateEndpoints">
      <arg name="uuid" type="s" direction="in"/>
      <arg name="replace" type="b" direction="in"/>
      <arg name="status" type="a{sv}" direction="out"/>
    </method>
    <method name="SetGuardOptions">
      <arg name="block_ipv6" type="b" direction="in"/>
      <arg name="interfaces" type="as" direction="in"/>
      <arg name="status" type="a{sv}" direction="out"/>
    </method>
    <method name="Disarm">
      <arg name="status" type="a{sv}" direction="out"/>
    </method>
    <method name="GetStatus">
      <arg name="status" type="a{sv}" direction="out"/>
    </method>
    <signal name="StateChanged">
      <arg name="status" type="a{sv}"/>
    </signal>
  </interface>
</node>
""".replace("@INTERFACE@", INTERFACE)


class ServiceError(RuntimeError):
    pass


class PermissionDenied(ServiceError):
    pass


class NotAvailable(ServiceError):
    pass


class NotArmed(ServiceError):
    pass


class ResolveFailed(ServiceError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def merge_endpoints(fresh, current) -> tuple[Endpoint, ...]:
    """Fresh endpoints first, then the current ones (kept for the live tunnel)."""
    merged: list[Endpoint] = []
    seen = set()
    for endpoint in (*fresh, *current):
        key = (endpoint.address, endpoint.port, endpoint.protocol)
        if key in seen:
            continue
        seen.add(key)
        merged.append(endpoint)
        if len(merged) >= MAX_ENDPOINTS:
            break
    return tuple(merged)


class SystemBackend:
    """Everything the service needs from the system; replaced in tests."""

    def nft_path(self) -> str:
        path = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
        if not path:
            raise NotAvailable("nftables is not installed")
        return path

    def run_nft(self, args: list[str], *, input_text: str | None = None) -> None:
        command = [self.nft_path(), *args]
        try:
            result = subprocess.run(
                command,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=NFT_TIMEOUT,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                check=False,
            )
        except FileNotFoundError as exc:
            raise NotAvailable("nftables is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise ServiceError("nftables command timed out") from exc
        except OSError as exc:
            raise ServiceError(f"could not run nftables: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            if len(detail) > 600:
                detail = detail[:600] + "…"
            raise ServiceError(f"nftables rejected the rules: {detail}")

    def table_exists(self, spec: str) -> bool:
        try:
            self.run_nft(["list", "table", *spec.split()])
        except ServiceError:
            return False
        return True

    def _client(self) -> NM.Client:
        try:
            client = NM.Client.new(None)
        except Exception as exc:
            raise ServiceError("NetworkManager is unavailable") from exc
        if client is None:
            raise ServiceError("NetworkManager is unavailable")
        return client

    def profile_remotes(self, uuid: str, uid: int, local_username) -> tuple[tuple, str]:
        """Load the reserved profile, check ownership, return (remotes, protocol)."""
        client = self._client()
        connection = None
        try:
            connection = client.get_connection_by_uuid(uuid)
        except Exception:
            connection = None
        if connection is None:
            raise ServiceError("managed profile not found")
        s_con = connection.get_setting_connection()
        s_vpn = connection.get_setting_vpn()
        if not isinstance(s_con, NM.SettingConnection) or not isinstance(s_vpn, NM.SettingVpn):
            raise ServiceError("managed profile is malformed")
        if s_vpn.get_service_type() != OPENVPN_SERVICE_TYPE:
            raise ServiceError("managed profile is not an OpenVPN connection")
        permissions = list(s_con.props.permissions or [])
        if uid == 0:
            if len(permissions) != 1:
                raise PermissionDenied("profile ownership is ambiguous")
            parts = permissions[0].split(":", 2)
            if len(parts) < 2 or parts[0] != "user":
                raise PermissionDenied("profile ownership is ambiguous")
            username = parts[1]
        else:
            username = local_username(uid)
        return remotes_from_profile_data(dict(s_vpn.props.data), permissions, username)

    def resolve_system(self, remotes, protocol: str) -> Resolution:
        text = ", ".join(f"[{h}]:{p}" if ":" in h else f"{h}:{p}" for h, p in remotes)
        return resolve_remotes(text, protocol)

    def resolve_direct(self, remotes, protocol: str, nameservers) -> Resolution:
        from .dnsquery import resolve_remotes_direct

        return resolve_remotes_direct(remotes, protocol, nameservers)

    def link_nameservers(self) -> list[str]:
        """DNS servers NetworkManager configured on the physical links."""
        servers: list[str] = []
        for device in self._client().get_devices():
            try:
                if device.get_iface() == TUNNEL_INTERFACE:
                    continue
                if device.get_state() != NM.DeviceState.ACTIVATED:
                    continue
                configs = (device.get_ip4_config(), device.get_ip6_config())
            except Exception:
                continue
            for config in configs:
                if config is None:
                    continue
                try:
                    servers.extend(str(item) for item in config.get_nameservers() or [])
                except Exception:
                    continue
        return servers

    def tunnel_up(self) -> bool:
        try:
            flags = int((Path("/sys/class/net") / TUNNEL_INTERFACE / "flags").read_text().strip(), 16)
        except (OSError, ValueError):
            return False
        return bool(flags & 0x1)

    def service_cgroup(self) -> str | None:
        """This process's cgroup v2 path, if it can be matched safely."""
        try:
            lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeDecodeError):
            return None
        for line in lines:
            if line.startswith("0::"):
                path = line[3:].strip().strip("/")
                if cgroup_match(path) is None or not (CGROUP_ROOT / path).is_dir():
                    return None
                return path
        return None

    def managed_vpn_active(self) -> bool:
        try:
            client = self._client()
        except ServiceError:
            return True  # unknown: leave the guard in place (fail closed)
        for active in client.get_active_connections():
            try:
                if active.get_uuid() == MANAGED_UUID and active.get_state() in (
                    NM.ActiveConnectionState.ACTIVATING,
                    NM.ActiveConnectionState.ACTIVATED,
                ):
                    return True
            except Exception:
                continue
        return False

    def active_vpn_gateways(self) -> list[str]:
        """Addresses of the server the managed VPN is connected to right now.

        NetworkManager routes the VPN server through the physical link with a
        host route (/32 or /128 with a next hop) while the VPN is up.  These
        are added to the allowlist when arming, so arming never cuts the
        tunnel that is already running, whatever the server names resolve to
        at that moment.
        """
        if not self.managed_vpn_active():
            return []
        addresses: list[str] = []
        try:
            devices = self._client().get_devices()
        except ServiceError:
            return []
        for device in devices:
            try:
                if device.get_iface() == TUNNEL_INTERFACE:
                    continue
                configs = (device.get_ip4_config(), device.get_ip6_config())
            except Exception:
                continue
            for config in configs:
                if config is None:
                    continue
                for route in config.get_routes() or []:
                    try:
                        full = route.get_prefix() == (32 if route.get_family() == 2 else 128)
                        if full and route.get_next_hop():
                            addresses.append(route.get_dest())
                    except Exception:
                        continue
        return addresses

    def write_guard_options(self, block_ipv6: bool, interfaces: tuple[str, ...]) -> None:
        """Write the leak guard's options for the dispatcher hook (root-owned, 0644)."""
        path = Path(GUARD_OPTIONS_PATH)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        data = (
            f"block-ipv6={'yes' if block_ipv6 else 'no'}\n"
            f"allowed-interfaces={','.join(interfaces)}\n"
        ).encode("ascii")
        fd, temporary = tempfile.mkstemp(prefix=".guard-", dir=path.parent)
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def apply_guard(self) -> None:
        """Run the dispatcher hook for the active managed VPN (as NetworkManager would)."""
        try:
            result = subprocess.run(
                ["/bin/sh", GUARD_HOOK, TUNNEL_INTERFACE, "vpn-up"],
                env={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LC_ALL": "C",
                    "CONNECTION_UUID": MANAGED_UUID,
                    "VPN_IP_IFACE": TUNNEL_INTERFACE,
                },
                capture_output=True,
                text=True,
                timeout=NFT_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ServiceError(f"could not run the leak guard hook: {exc}") from exc
        if result.returncode != 0:
            raise ServiceError(f"the leak guard hook failed: {(result.stderr or '').strip()[:300]}")

    def clock(self) -> float:
        return time.monotonic()


class KillSwitchService:
    def __init__(self, backend: SystemBackend | None = None, *, state_file: Path = STATE_FILE):
        self.backend = backend or SystemBackend()
        self.state_file = state_file
        self._connection: Gio.DBusConnection | None = None
        self._registration_id: int | None = None
        self._armed = False
        self._state = "off"
        self._detail = "Not armed"
        self._uuid = ""
        self._allow_lan = False
        self._interfaces: tuple[str, ...] = ()
        self._since = ""
        self._resolved_at = ""
        self._owner_uid: int | None = None
        self._endpoints: tuple[Endpoint, ...] = ()
        self._window_rule = False
        self._last_window: float | None = None

    # ------------------------------------------------------------- lifecycle

    def start(self) -> bool:
        try:
            Gio.bus_own_name(
                Gio.BusType.SYSTEM,
                BUS_NAME,
                Gio.BusNameOwnerFlags.NONE,
                self._on_bus_acquired,
                None,
                self._on_name_lost,
            )
        except GLib.Error as exc:
            log.error("could not own %s: %s", BUS_NAME, exc.message)
            return False
        self._recover_state()
        self._sync_guard()
        return True

    def _on_bus_acquired(self, connection: Gio.DBusConnection, _name: str):
        self._connection = connection
        node = Gio.DBusNodeInfo.new_for_xml(_INTROSPECTION_XML)
        try:
            self._registration_id = connection.register_object(
                OBJECT_PATH,
                node.interfaces[0],
                self._on_method_call,
                None,
                None,
            )
        except GLib.Error as exc:
            log.error("could not register kill-switch object: %s", exc.message)
            return
        log.info("kill-switch service ready")
        self._emit_status()

    def _on_name_lost(self, _connection, _name: str):
        log.error("lost the D-Bus name %s", BUS_NAME)

    # ---------------------------------------------------------------- status

    def status(self) -> dict[str, GLib.Variant]:
        return {
            "armed": GLib.Variant("b", self._armed),
            "state": GLib.Variant("s", self._state),
            "detail": GLib.Variant("s", self._detail),
            "uuid": GLib.Variant("s", self._uuid),
            "allow_lan": GLib.Variant("b", self._allow_lan),
            "interfaces": GLib.Variant("as", list(self._interfaces)),
            "endpoints": GLib.Variant("u", len(self._endpoints)),
            "resolved_at": GLib.Variant("s", self._resolved_at),
            "guard": GLib.Variant("b", self.backend.table_exists(GUARD_TABLE_SPEC)),
            "backend": GLib.Variant("s", "nftables"),
            "table": GLib.Variant("s", TABLE_SPEC),
            "since": GLib.Variant("s", self._since),
        }

    def _reply(self, resolved: tuple[Endpoint, ...] | None = None) -> GLib.Variant:
        status = self.status()
        if resolved is not None:
            # Only the authorized caller gets the addresses, to pin its profile;
            # GetStatus and StateChanged carry a count only.
            status["resolved"] = GLib.Variant(
                "a(sqs)", [(e.address, e.port, e.protocol) for e in resolved]
            )
        return GLib.Variant("(a{sv})", (status,))

    def _emit_status(self):
        if self._connection is None or self._registration_id is None:
            return
        try:
            self._connection.emit_signal(
                None,
                OBJECT_PATH,
                INTERFACE,
                "StateChanged",
                GLib.Variant("(a{sv})", (self.status(),)),
            )
        except GLib.Error as exc:
            log.warning("could not emit StateChanged: %s", exc.message)

    # ------------------------------------------------------------ D-Bus calls

    def _on_method_call(
        self,
        _connection,
        sender,
        _path,
        interface,
        method_name,
        parameters,
        invocation,
    ):
        if interface != INTERFACE:
            invocation.return_dbus_error(OPERATION_FAILED, "unknown interface")
            return None
        try:
            invocation.return_value(self.handle(method_name, parameters.unpack(), sender))
        except PermissionDenied as exc:
            invocation.return_dbus_error(PERMISSION_DENIED, str(exc))
        except NotAvailable as exc:
            invocation.return_dbus_error(NOT_AVAILABLE, str(exc))
        except NotArmed as exc:
            invocation.return_dbus_error(NOT_ARMED, str(exc))
        except ResolveFailed as exc:
            invocation.return_dbus_error(RESOLVE_FAILED, str(exc))
        except (ServiceError, ProfileError, RulesError) as exc:
            invocation.return_dbus_error(OPERATION_FAILED, str(exc))
        except Exception as exc:
            log.exception("kill-switch method %s failed", method_name)
            invocation.return_dbus_error(OPERATION_FAILED, f"operation failed: {exc}")
        return None

    def handle(self, method_name: str, args: tuple, sender: str | None) -> GLib.Variant:
        if method_name == "GetStatus":
            return self._reply()
        if method_name not in {"Arm", "Configure", "UpdateEndpoints", "SetGuardOptions", "Disarm"}:
            raise ServiceError("unknown method")
        uid = self.caller_uid(sender)
        self.authorize(sender, uid)
        if method_name == "Arm":
            uuid, allow_lan, interfaces = args
            return self._reply(self.arm(str(uuid), bool(allow_lan), list(interfaces), uid))
        if method_name == "Configure":
            allow_lan, interfaces = args
            self.configure(bool(allow_lan), list(interfaces), uid)
            return self._reply()
        if method_name == "UpdateEndpoints":
            uuid, replace = args
            return self._reply(self.update_endpoints(str(uuid), bool(replace), uid))
        if method_name == "SetGuardOptions":
            block_ipv6, interfaces = args
            self.set_guard_options(bool(block_ipv6), list(interfaces), uid)
            return self._reply()
        self.disarm(uid)
        return self._reply()

    # ------------------------------------------------------------- authority

    def caller_uid(self, sender: str | None) -> int:
        if not sender or self._connection is None:
            raise PermissionDenied("could not identify the caller")
        try:
            reply = self._connection.call_sync(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixUser",
                GLib.Variant("(s)", (sender,)),
                GLib.VariantType("(u)"),
                Gio.DBusCallFlags.NONE,
                3000,
                None,
            )
            return int(reply.unpack()[0])
        except Exception as exc:
            raise PermissionDenied("could not identify the caller") from exc

    def authorize(self, sender: str | None, uid: int):
        if uid == 0:
            return
        subject = (
            "system-bus-name",
            {"name": GLib.Variant("s", sender or "")},
        )
        try:
            reply = self._connection.call_sync(
                "org.freedesktop.PolicyKit1",
                "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority",
                "CheckAuthorization",
                GLib.Variant(
                    "((sa{sv})sa{ss}us)",
                    (subject, POLKIT_ACTION, {}, 1, ""),
                ),
                GLib.VariantType("((bba{ss}))"),
                Gio.DBusCallFlags.NONE,
                10000,
                None,
            )
        except Exception as exc:
            log.exception("polkit CheckAuthorization failed")
            raise PermissionDenied("polkit authorization failed") from exc
        try:
            authorized = bool(reply.unpack()[0][0])
        except (IndexError, TypeError) as exc:
            raise PermissionDenied("polkit returned a malformed reply") from exc
        if not authorized:
            raise PermissionDenied("not authorized to control the kill switch")

    @staticmethod
    def local_username(uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError as exc:
            raise PermissionDenied("caller has no local account") from exc

    def _require_owner(self, uid: int):
        """The Disarm restriction: only the arming user, or root."""
        if self._owner_uid is not None and uid not in {0, self._owner_uid}:
            raise PermissionDenied("only the user who armed the kill switch may change it")

    def _require_armed(self):
        if not self._armed or self._state != "armed":
            raise NotArmed("the kill switch is not armed")

    def _profile_remotes(self, uuid: str, uid: int):
        if uuid != MANAGED_UUID:
            raise PermissionDenied("this service only protects the reserved Pervius profile")
        return self.backend.profile_remotes(uuid, uid, self.local_username)

    # -------------------------------------------------------------- nftables

    def _apply_rules(self, endpoints, allow_lan: bool, interfaces: tuple[str, ...]):
        cgroup = self.backend.service_cgroup()
        rules = build_ruleset(
            endpoints, allow_lan=allow_lan, interfaces=interfaces, service_cgroup=cgroup
        )
        self.backend.run_nft(["-f", "-"], input_text=rules)
        if not self.backend.table_exists(TABLE_SPEC):
            raise ServiceError("nftables did not create the Pervius table")
        self._window_rule = cgroup is not None
        log.info(
            "kill-switch rules applied: %d endpoint(s), %d extra interface(s), allow_lan=%s, dns window=%s",
            len(tuple(endpoints)),
            len(interfaces),
            allow_lan,
            "available" if self._window_rule else "unavailable",
        )

    def _delete_rules(self):
        if not self.backend.table_exists(TABLE_SPEC):
            return
        self.backend.run_nft(["delete", "table", *TABLE_SPEC.split()])
        if self.backend.table_exists(TABLE_SPEC):
            raise ServiceError("Pervius nftables table still exists after deletion")
        log.info("kill switch disarmed")

    # ----------------------------------------------------------------- arm

    def arm(self, uuid: str, allow_lan: bool, interfaces: list, uid: int) -> tuple[Endpoint, ...]:
        validated = validate_interfaces(interfaces)
        if self._armed:
            if (
                self._state == "armed"
                and self._uuid == uuid
                and self._allow_lan == allow_lan
                and self._interfaces == validated
                and uid in {0, self._owner_uid}
            ):
                self._detail = "Already armed"
                return self._endpoints
            raise ServiceError("kill switch is already armed; disarm it first")

        remotes, protocol = self._profile_remotes(uuid, uid)
        # No Pervius rules exist yet, so this uses the system resolver (through
        # the tunnel's DNS when the VPN is up).  The server of a live tunnel is
        # always allowed, so arming never cuts it.
        live = self._live_endpoints(remotes, protocol)
        try:
            resolution = self.backend.resolve_system(remotes, protocol)
        except RulesError:
            if not live:
                raise
            resolution = Resolution(live, ("server names did not resolve; using the live server",))
        self._log_warnings(resolution)
        endpoints = merge_endpoints(resolution.endpoints, live)
        self._apply_rules(endpoints, allow_lan, validated)
        self._armed = True
        self._state = "armed"
        self._detail = "Rules installed; VPN may still be connecting"
        self._uuid = uuid
        self._allow_lan = allow_lan
        self._interfaces = validated
        self._owner_uid = uid
        self._since = utc_now()
        self._resolved_at = self._since
        self._endpoints = endpoints
        self._save_state()
        self._emit_status()
        return endpoints

    def configure(self, allow_lan: bool, interfaces: list, uid: int):
        self._require_armed()
        self._require_owner(uid)
        validated = validate_interfaces(interfaces)
        self._apply_rules(self._endpoints, allow_lan, validated)
        self._allow_lan = allow_lan
        self._interfaces = validated
        self._detail = "Settings applied"
        self._save_state()
        self._emit_status()

    def update_endpoints(self, uuid: str, replace: bool, uid: int) -> tuple[Endpoint, ...]:
        self._require_armed()
        self._require_owner(uid)
        if uuid != self._uuid:
            raise PermissionDenied("the kill switch protects a different profile")
        remotes, protocol = self._profile_remotes(uuid, uid)
        try:
            resolution = None
            if self.backend.tunnel_up():
                try:
                    resolution = self.backend.resolve_system(remotes, protocol)
                except RulesError as exc:
                    # The tunnel may be up but not carrying DNS (for example
                    # after the server stopped answering): try the window.
                    log.warning("resolving through the tunnel failed: %s", exc)
            if resolution is None:
                resolution = self._resolve_through_window(remotes, protocol)
        except ResolveFailed as exc:
            log.warning("could not update the VPN server addresses: %s", exc)
            raise
        self._log_warnings(resolution)
        # The live tunnel's server always stays allowed, even when replacing:
        # dropping it would cut the tunnel before the switch completes (the
        # old OpenVPN process then cannot even say goodbye and holds the
        # tunnel device for seconds).
        live = self._live_endpoints(remotes, protocol)
        if replace:
            endpoints = merge_endpoints(resolution.endpoints, live)
        else:
            endpoints = merge_endpoints(resolution.endpoints, (*self._endpoints, *live))
        # One transaction: new endpoint sets in, DNS window closed.
        self.backend.run_nft(["-f", "-"], input_text=build_endpoint_swap(endpoints))
        self._endpoints = endpoints
        self._resolved_at = utc_now()
        self._detail = "VPN server addresses updated"
        self._save_state()
        self._emit_status()
        log.info("endpoints updated: %d (%s)", len(endpoints), "replaced" if replace else "merged")
        return resolution.endpoints

    def _live_endpoints(self, remotes, protocol: str) -> tuple[Endpoint, ...]:
        """The live VPN server, on the profile's ports and protocol."""
        ports = sorted({port for _host, port in remotes})
        endpoints = []
        try:
            gateways = self.backend.active_vpn_gateways()
        except Exception as exc:
            log.warning("could not read the live VPN server: %s", exc)
            gateways = []
        for address in gateways:
            for port in ports:
                try:
                    endpoints.append(Endpoint(address, port, protocol))
                except RulesError:
                    continue
        if endpoints:
            log.info("keeping the live VPN server allowed (%d endpoint(s))", len(endpoints))
        return tuple(endpoints)

    def set_guard_options(self, block_ipv6: bool, interfaces: list, uid: int):
        """Options for the leak guard (NetworkManager dispatcher hook).

        Only the owner of the managed profile may set them.  They take effect
        when the VPN next comes up.
        """
        validated = validate_interfaces(interfaces)
        self._profile_remotes(MANAGED_UUID, uid)  # ownership check
        try:
            self.backend.write_guard_options(block_ipv6, validated)
        except OSError as exc:
            raise ServiceError(f"could not save the leak guard options: {exc}") from exc
        log.info("leak guard options saved: block_ipv6=%s, %d interface(s)", block_ipv6, len(validated))
        self._sync_guard(reapply=True)

    def _resolve_through_window(self, remotes, protocol: str) -> Resolution:
        """Resolve server names while the tunnel is down.

        The DNS window admits only this service's own queries (cgroup match),
        only to the link's resolvers, only plain DNS, and expires in the
        kernel after a few seconds even if the service dies.
        """
        if not self._window_rule:
            raise ResolveFailed("the DNS window is unavailable (cgroup v2 match not possible)")
        now = self.backend.clock()
        if self._last_window is not None and now - self._last_window < DNS_WINDOW_INTERVAL:
            raise ResolveFailed("the DNS window was used moments ago; try again shortly")
        servers = resolver_addresses(self.backend.link_nameservers())
        if not servers:
            raise ResolveFailed("no DNS server is configured on the network links")
        self._last_window = now
        self.backend.run_nft(["-f", "-"], input_text=build_dns_window(servers))
        log.info("DNS window opened for %d resolver(s)", len(servers))
        try:
            return self.backend.resolve_direct(remotes, protocol, servers)
        except Exception as exc:
            try:
                self.backend.run_nft(["-f", "-"], input_text=build_dns_window_close())
            except ServiceError:
                log.warning("could not close the DNS window early; it expires on its own")
            raise ResolveFailed(f"could not resolve the VPN servers: {exc}") from exc

    @staticmethod
    def _log_warnings(resolution: Resolution):
        for warning in resolution.warnings:
            log.warning("endpoint warning: %s", warning)

    def disarm(self, uid: int):
        if self._armed:
            self._require_owner(uid)
        self._delete_rules()
        self._armed = False
        self._state = "off"
        self._detail = "Not armed"
        self._uuid = ""
        self._allow_lan = False
        self._interfaces = ()
        self._owner_uid = None
        self._since = ""
        self._resolved_at = ""
        self._endpoints = ()
        self._window_rule = False
        self._delete_state()
        self._emit_status()

    # ---------------------------------------------------------------- state

    def _save_state(self):
        directory = self.state_file.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        payload = {
            "version": STATE_VERSION,
            "armed": True,
            "uuid": self._uuid,
            "allow_lan": self._allow_lan,
            "interfaces": list(self._interfaces),
            "owner_uid": self._owner_uid,
            "since": self._since,
            "resolved_at": self._resolved_at,
            "state": self._state,
            "detail": self._detail,
            "endpoints": [
                {"address": e.address, "port": e.port, "protocol": e.protocol}
                for e in self._endpoints
            ],
        }
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        fd, temporary = tempfile.mkstemp(prefix=".killswitch-", dir=directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_file)
            os.chmod(self.state_file, 0o600)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def load_state(self) -> dict | None:
        try:
            value = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(value, dict) or value.get("version") not in {1, STATE_VERSION}:
            return None
        if value.get("uuid") != MANAGED_UUID or not isinstance(value.get("allow_lan"), bool):
            return None
        try:
            endpoints = endpoints_from_state(value.get("endpoints") or [])
            # Version 1 had no interface list (it allowed tun*).
            interfaces = validate_interfaces(value.get("interfaces") or [])
        except (RulesError, TypeError, ValueError):
            return None
        owner = value.get("owner_uid")
        if not isinstance(owner, int) or isinstance(owner, bool):
            return None
        return {
            "uuid": MANAGED_UUID,
            "allow_lan": value["allow_lan"],
            "interfaces": interfaces,
            "owner_uid": owner,
            "since": str(value.get("since") or utc_now()),
            "resolved_at": str(value.get("resolved_at") or value.get("since") or ""),
            "endpoints": endpoints,
            "version": value["version"],
        }

    def _delete_state(self):
        try:
            self.state_file.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.warning("could not remove kill-switch state: %s", exc)

    def _restore(self, state: dict, detail: str):
        self._armed = True
        self._state = "armed"
        self._detail = detail
        self._uuid = state["uuid"]
        self._allow_lan = state["allow_lan"]
        self._interfaces = state["interfaces"]
        self._owner_uid = state["owner_uid"]
        self._since = state["since"]
        self._resolved_at = state["resolved_at"]
        self._endpoints = state["endpoints"]

    def _recover_state(self):
        table = self.backend.table_exists(TABLE_SPEC)
        state = self.load_state()
        if table and state is None:
            self._armed = True
            self._state = "error"
            self._detail = (
                "Pervius firewall table exists without recoverable state; "
                "Disarm before arming again"
            )
            log.error(self._detail)
            return
        if state is None:
            self._armed = False
            self._state = "off"
            self._detail = "Not armed"
            return
        # Rebuild in one transaction even when the table survived: the DNS
        # window rule names this process's cgroup, which a restart replaces,
        # and a version-1 table used the old layout.
        try:
            self._apply_rules(state["endpoints"], state["allow_lan"], state["interfaces"])
        except Exception as exc:
            self._armed = table
            self._state = "error"
            self._detail = f"Could not restore protection: {exc}"
            log.error(self._detail)
            return
        self._restore(
            state,
            "Protection restored after service restart"
            if table
            else "Protection reconstructed after service restart",
        )
        if state["version"] != STATE_VERSION:
            self._save_state()
        log.info("restored kill-switch state with %d endpoint(s)", len(self._endpoints))

    def _sync_guard(self, *, reapply: bool = False):
        """Make the leak guard match the VPN's real state.

        The dispatcher hook installs the guard when the VPN comes up.  A VPN
        that was already up when Pervius was installed or upgraded never saw
        that event, so the service applies the guard to it (by running the
        same hook); ``reapply`` does so after the options changed.  A guard
        left behind after a NetworkManager crash is removed.
        """
        try:
            active = self.backend.managed_vpn_active()
            if active:
                if reapply or not self.backend.table_exists(GUARD_TABLE_SPEC):
                    self.backend.apply_guard()
                    log.info("leak guard applied to the active VPN")
                return
            for spec in (GUARD_TABLE_SPEC, LEGACY_GUARD_TABLE_SPEC):
                if self.backend.table_exists(spec):
                    self.backend.run_nft(["delete", "table", *spec.split()])
                    log.info("removed a stale leak guard %s (the managed VPN is not active)", spec)
        except Exception as exc:
            log.warning("could not synchronise the leak guard: %s", exc)

    # Kept for callers and tests from before the guard was synchronised.
    _clear_stale_guard = _sync_guard


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s pervius-killswitchd[%(process)d]: %(levelname)s %(message)s",
    )
    if os.geteuid() != 0:
        sys.stderr.write("pervius-killswitchd must run as root\n")
        return 1
    service = KillSwitchService()
    if not service.start():
        return 1
    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
