from __future__ import annotations

import unittest

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib  # noqa: E402

from solvetus.config import (
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
)
from solvetus.nm.agent import (
    NOT_AUTHORIZED,
    AgentError,
    NetworkManagerSecretAgent,
    _unpack_connection_hash,
    ownership_matches,
)
from solvetus.ownership import OwnershipEntry

USER = "tester"


def connection_hash(
    *,
    uuid: str = MANAGED_UUID,
    connection_id: str = MANAGED_CONNECTION_ID,
    service: str = OPENVPN_SERVICE_TYPE,
    permissions: list[str] | None = None,
) -> dict:
    return {
        "connection": {
            "uuid": GLib.Variant("s", uuid),
            "id": GLib.Variant("s", connection_id),
            "permissions": GLib.Variant("as", permissions if permissions is not None else [f"user:{USER}"]),
        },
        "vpn": {"service-type": GLib.Variant("s", service)},
    }


class AgentValidationTests(unittest.TestCase):
    def test_valid_hash(self):
        self.assertEqual(
            _unpack_connection_hash(connection_hash(), USER),
            (MANAGED_UUID, MANAGED_CONNECTION_ID, OPENVPN_SERVICE_TYPE),
        )

    def test_wrong_uuid_rejected(self):
        with self.assertRaises(AgentError) as caught:
            _unpack_connection_hash(
                connection_hash(uuid="11111111-1111-1111-1111-111111111111"), USER
            )
        self.assertEqual(caught.exception.dbus_name, NOT_AUTHORIZED)
        self.assertIn("UUID", str(caught.exception))

    def test_wrong_id_rejected(self):
        with self.assertRaisesRegex(AgentError, "ID"):
            _unpack_connection_hash(connection_hash(connection_id="Other"), USER)

    def test_wrong_service_rejected(self):
        with self.assertRaisesRegex(AgentError, "not an OpenVPN"):
            _unpack_connection_hash(connection_hash(service="org.example.other"), USER)

    def test_missing_permission_rejected(self):
        with self.assertRaisesRegex(AgentError, "not restricted"):
            _unpack_connection_hash(connection_hash(permissions=[]), USER)

    def test_other_user_permission_rejected(self):
        with self.assertRaisesRegex(AgentError, "not restricted"):
            _unpack_connection_hash(connection_hash(permissions=["user:someone-else"]), USER)

    def test_libnm_trailing_detail_is_accepted(self):
        self.assertEqual(
            _unpack_connection_hash(connection_hash(permissions=[f"user:{USER}:"]), USER),
            (MANAGED_UUID, MANAGED_CONNECTION_ID, OPENVPN_SERVICE_TYPE),
        )

    def test_group_permission_is_rejected(self):
        with self.assertRaisesRegex(AgentError, "not restricted"):
            _unpack_connection_hash(connection_hash(permissions=["group:wheel"]), USER)

    def test_malformed_hash_rejected(self):
        with self.assertRaises(AgentError):
            _unpack_connection_hash({"connection": {}, "vpn": {}}, USER)
        with self.assertRaises(AgentError):
            _unpack_connection_hash({"connection": {"uuid": "x"}}, USER)

    def test_manifest_matching(self):
        self.assertTrue(ownership_matches(OwnershipEntry()))
        self.assertFalse(ownership_matches(None))
        self.assertFalse(ownership_matches(OwnershipEntry(uuid="not-ours")))
        self.assertFalse(ownership_matches(OwnershipEntry(service_type="org.example.other")))

    def test_agent_starts_unregistered(self):
        agent = NetworkManagerSecretAgent(
            lambda _username: None,
            username=USER,
            store_provider=lambda: None,  # type: ignore[arg-type]
        )
        self.assertFalse(agent.registered)

    def test_agent_does_not_release_password_without_manifest(self):
        agent = NetworkManagerSecretAgent(
            lambda _username: "password",
            username=USER,
            store_provider=lambda: _EmptyStore(),
        )
        self.assertIsNone(agent._manifest_entry())


class _EmptyStore:
    def get(self, _uuid):
        return None


if __name__ == "__main__":
    unittest.main()
