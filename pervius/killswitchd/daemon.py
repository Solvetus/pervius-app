"""Pervius kill-switch system service.

Runs as root under systemd.  It owns exactly one nftables table, never flushes
the global ruleset, and never invokes a shell.  The public D-Bus surface is
limited to arming and disarming protection for the reserved app-owned profile.
"""

from __future__ import annotations

import logging
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gio", "2.0")
gi.require_version("NM", "1.0")
from gi.repository import Gio, GLib, NM  # noqa: E402

from ..config import MANAGED_UUID, OPENVPN_SERVICE_TYPE  # noqa: E402
from .profile import ProfileError, endpoints_from_profile_data  # noqa: E402
from .rules import (  # noqa: E402
    TABLE_SPEC,
    Endpoint,
    RulesError,
    build_ruleset,
    endpoints_from_state,
)

log = logging.getLogger(__name__)

BUS_NAME = "com.solvetus.Pervius.KillSwitch1"
OBJECT_PATH = "/com/solvetus/Pervius/KillSwitch1"
INTERFACE = "com.solvetus.Pervius.KillSwitch1"
POLKIT_ACTION = "com.solvetus.pervius.killswitch.control"
STATE_DIR = Path("/run/pervius")
STATE_FILE = STATE_DIR / "killswitch.json"
STATE_VERSION = 1
NFT_TIMEOUT = 20

PERMISSION_DENIED = f"{INTERFACE}.PermissionDenied"
OPERATION_FAILED = f"{INTERFACE}.Failed"
NOT_AVAILABLE = f"{INTERFACE}.NotAvailable"

_INTROSPECTION_XML = """
<node>
  <interface name="@INTERFACE@">
    <method name="Arm">
      <arg name="uuid" type="s" direction="in"/>
      <arg name="allow_lan" type="b" direction="in"/>
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


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class KillSwitchService:
    def __init__(self):
        self._connection: Gio.DBusConnection | None = None
        self._registration_id: int | None = None
        self._armed = False
        self._state = "off"
        self._detail = "Not armed"
        self._uuid = ""
        self._allow_lan = False
        self._since = ""
        self._owner_uid: int | None = None
        self._endpoints: tuple[Endpoint, ...] = ()

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

    def _status(self) -> dict[str, GLib.Variant]:
        return {
            "armed": GLib.Variant("b", self._armed),
            "state": GLib.Variant("s", self._state),
            "detail": GLib.Variant("s", self._detail),
            "uuid": GLib.Variant("s", self._uuid),
            "allow_lan": GLib.Variant("b", self._allow_lan),
            "endpoints": GLib.Variant("u", len(self._endpoints)),
            "backend": GLib.Variant("s", "nftables"),
            "table": GLib.Variant("s", TABLE_SPEC),
            "since": GLib.Variant("s", self._since),
        }

    def _status_variant(self) -> GLib.Variant:
        return GLib.Variant("(a{sv})", (self._status(),))

    def _emit_status(self):
        if self._connection is None or self._registration_id is None:
            return
        try:
            self._connection.emit_signal(
                None,
                OBJECT_PATH,
                INTERFACE,
                "StateChanged",
                GLib.Variant("(a{sv})", (self._status(),)),
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
            if method_name == "GetStatus":
                invocation.return_value(self._status_variant())
                return None

            if method_name == "Arm":
                uuid, allow_lan = parameters.unpack()
                uid = self._caller_uid(sender)
                self._authorize(sender)
                self._arm(str(uuid), bool(allow_lan), uid)
                invocation.return_value(self._status_variant())
                return None

            if method_name == "Disarm":
                uid = self._caller_uid(sender)
                self._authorize(sender)
                self._disarm(uid)
                invocation.return_value(self._status_variant())
                return None

            invocation.return_dbus_error(OPERATION_FAILED, "unknown method")
        except PermissionDenied as exc:
            invocation.return_dbus_error(PERMISSION_DENIED, str(exc))
        except NotAvailable as exc:
            invocation.return_dbus_error(NOT_AVAILABLE, str(exc))
        except (ServiceError, ProfileError, RulesError) as exc:
            invocation.return_dbus_error(OPERATION_FAILED, str(exc))
        except Exception as exc:
            log.exception("kill-switch method %s failed", method_name)
            invocation.return_dbus_error(OPERATION_FAILED, f"operation failed: {exc}")
        return None

    # ------------------------------------------------------------- authority

    def _caller_uid(self, sender: str | None) -> int:
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

    def _authorize(self, sender: str | None):
        uid = self._caller_uid(sender)
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

    def _local_username(self, uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError as exc:
            raise PermissionDenied("caller has no local account") from exc

    # ------------------------------------------------------------- nftables

    def _nft(self) -> str:
        path = shutil.which("nft")
        if not path:
            raise NotAvailable("nftables is not installed")
        return path

    def _run_nft(self, args: list[str], *, input_text: str | None = None):
        command = [self._nft(), *args]
        try:
            result = subprocess.run(
                command,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=NFT_TIMEOUT,
                env={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LC_ALL": "C",
                },
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
        return result

    def _table_exists(self) -> bool:
        try:
            result = subprocess.run(
                [self._nft(), "list", "table", TABLE_SPEC],
                text=True,
                capture_output=True,
                timeout=NFT_TIMEOUT,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                check=False,
            )
        except Exception:
            return False
        return result.returncode == 0

    def _apply_rules(self, endpoints: tuple[Endpoint, ...], allow_lan: bool):
        rules = build_ruleset(endpoints, allow_lan=allow_lan)
        self._run_nft(["-f", "-"], input_text=rules)
        if not self._table_exists():
            raise ServiceError("nftables did not create the Pervius table")
        log.info("kill switch armed with %d endpoint(s), allow_lan=%s", len(endpoints), allow_lan)

    def _delete_rules(self):
        if not self._table_exists():
            return
        self._run_nft(["delete", "table", TABLE_SPEC])
        if self._table_exists():
            raise ServiceError("Pervius nftables table still exists after deletion")
        log.info("kill switch disarmed")

    # -------------------------------------------------------------- profile

    def _load_profile(self, uuid: str, uid: int) -> tuple[Endpoint, ...]:
        if uuid != MANAGED_UUID:
            raise PermissionDenied("this service only protects the reserved Pervius profile")
        try:
            client = NM.Client.new(None)
        except Exception as exc:
            raise ServiceError("NetworkManager is unavailable") from exc
        if client is None:
            raise ServiceError("NetworkManager is unavailable")
        connection = None
        try:
            connection = client.get_connection_by_uuid(uuid)
        except Exception:
            connection = None
        if connection is None:
            for candidate in client.get_connections():
                try:
                    if candidate.get_uuid() == uuid:
                        connection = candidate
                        break
                except Exception:
                    continue
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
            username = self._local_username(uid)
        data = dict(s_vpn.props.data)
        result = endpoints_from_profile_data(data, permissions, username)
        for warning in result.warnings:
            log.warning("profile endpoint warning: %s", warning)
        return result.endpoints

    # ---------------------------------------------------------------- state

    def _arm(self, uuid: str, allow_lan: bool, uid: int):
        if self._armed:
            if self._state == "armed" and self._uuid == uuid and self._allow_lan == allow_lan:
                self._detail = "Already armed"
                return
            raise ServiceError("kill switch is already armed; disarm it first")

        endpoints = self._load_profile(uuid, uid)
        self._apply_rules(endpoints, allow_lan)
        self._armed = True
        self._state = "armed"
        self._detail = "Rules installed; VPN may still be connecting"
        self._uuid = uuid
        self._allow_lan = allow_lan
        self._owner_uid = uid
        self._since = utc_now()
        self._endpoints = endpoints
        self._save_state()
        self._emit_status()

    def _disarm(self, uid: int):
        if self._armed and self._owner_uid is not None and uid not in {0, self._owner_uid}:
            raise PermissionDenied("only the user who armed the kill switch may disarm it")
        self._delete_rules()
        self._armed = False
        self._state = "off"
        self._detail = "Not armed"
        self._uuid = ""
        self._allow_lan = False
        self._owner_uid = None
        self._since = ""
        self._endpoints = ()
        self._delete_state()
        self._emit_status()

    def _ensure_state_dir(self):
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(STATE_DIR, 0o700)

    def _save_state(self):
        self._ensure_state_dir()
        payload = {
            "version": STATE_VERSION,
            "armed": True,
            "uuid": self._uuid,
            "allow_lan": self._allow_lan,
            "owner_uid": self._owner_uid,
            "since": self._since,
            "state": self._state,
            "detail": self._detail,
            "endpoints": [
                {
                    "address": endpoint.address,
                    "port": endpoint.port,
                    "protocol": endpoint.protocol,
                }
                for endpoint in self._endpoints
            ],
        }
        import json

        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        fd, temporary = tempfile.mkstemp(prefix=".killswitch-", dir=STATE_DIR)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, STATE_FILE)
            os.chmod(STATE_FILE, 0o600)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _load_state(self) -> dict | None:
        try:
            import json

            value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(value, dict) or value.get("version") != STATE_VERSION:
            return None
        if not value.get("uuid") or not isinstance(value.get("allow_lan"), bool):
            return None
        try:
            endpoints = endpoints_from_state(value.get("endpoints") or [])
        except (RulesError, TypeError, ValueError):
            return None
        owner = value.get("owner_uid")
        if not isinstance(owner, int):
            return None
        return {
            "uuid": str(value["uuid"]),
            "allow_lan": bool(value["allow_lan"]),
            "owner_uid": owner,
            "since": str(value.get("since") or utc_now()),
            "endpoints": endpoints,
        }

    def _delete_state(self):
        try:
            STATE_FILE.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.warning("could not remove kill-switch state: %s", exc)

    def _recover_state(self):
        if self._table_exists():
            state = self._load_state()
            if state is None:
                self._armed = True
                self._state = "error"
                self._detail = (
                    "Pervius firewall table exists without recoverable state; "
                    "Disarm before arming again"
                )
                log.error(self._detail)
                return
            self._armed = True
            self._state = "armed"
            self._detail = "Protection restored after service restart"
            self._uuid = state["uuid"]
            self._allow_lan = state["allow_lan"]
            self._owner_uid = state["owner_uid"]
            self._since = state["since"]
            self._endpoints = state["endpoints"]
            log.info("restored kill-switch state with %d endpoint(s)", len(self._endpoints))
            return

        state = self._load_state()
        if state is None:
            self._armed = False
            self._state = "off"
            self._detail = "Not armed"
            return
        # The table disappeared while state survived: reconstruct and verify.
        try:
            self._apply_rules(state["endpoints"], state["allow_lan"])
        except Exception as exc:
            self._armed = False
            self._state = "error"
            self._detail = f"Could not restore protection: {exc}"
            log.error(self._detail)
            return
        self._armed = True
        self._state = "armed"
        self._detail = "Protection reconstructed after service restart"
        self._uuid = state["uuid"]
        self._allow_lan = state["allow_lan"]
        self._owner_uid = state["owner_uid"]
        self._since = state["since"]
        self._endpoints = state["endpoints"]


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
