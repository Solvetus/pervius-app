from __future__ import annotations

import unittest

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib  # noqa: E402

from pervius.config import (
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
)
from pervius.nm.agent import (
    NOT_AUTHORIZED,
    AgentError,
    NetworkManagerSecretAgent,
    _unpack_connection_hash,
    ownership_matches,
)
from pervius.ownership import OwnershipEntry

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
            _EmptyStore(),
            lambda: "vpnuser@example",
            username=USER,
            store_provider=lambda: None,  # type: ignore[arg-type]
        )
        self.assertFalse(agent.registered)

    def test_agent_does_not_release_password_without_manifest(self):
        agent = NetworkManagerSecretAgent(
            _EmptyStore(),
            lambda: "vpnuser@example",
            username=USER,
            store_provider=lambda: _EmptyStore(),
        )
        self.assertIsNone(agent._manifest_entry())


class _EmptyStore:
    def get(self, _uuid):
        return None




class AsyncSecretTests(unittest.TestCase):
    """GetSecrets must never block the main loop on the keyring."""

    def make_agent(self, store):
        agent = NetworkManagerSecretAgent(store, lambda: "vpnuser@example", username=USER)
        agent._sender_is_root = lambda sender: True
        agent._manifest_entry = lambda: OwnershipEntry()
        return agent

    def call(self, agent):
        class Invocation:
            def __init__(self):
                self.value = None
                self.error = None

            def return_value(self, value):
                self.value = value

            def return_dbus_error(self, name, message):
                self.error = (name, message)

        invocation = Invocation()
        params = GLib.Variant(
            "(a{sa{sv}}osasu)",
            (connection_hash(), "/org/freedesktop/NetworkManager/Settings/1", "vpn", [], 0),
        )
        agent._on_method_call(None, ":1.1", "/", "", "GetSecrets", params, invocation)
        return invocation

    def test_reply_is_deferred_until_the_keyring_answers(self):
        pending = []

        class Store:
            def lookup(self, _username):
                raise AssertionError("synchronous keyring lookup on the main loop")

            def lookup_async(self, username, callback):
                pending.append((username, callback))

        agent = self.make_agent(Store())
        invocation = self.call(agent)
        # Returned immediately, nothing answered yet.
        self.assertIsNone(invocation.value)
        self.assertIsNone(invocation.error)
        self.assertEqual([name for name, _cb in pending], ["vpnuser@example"])
        pending[0][1]("secret")
        self.assertEqual(invocation.value.unpack()[0]["vpn"]["password"], "secret")

    def test_no_password_answers_no_secrets(self):
        class Store:
            def lookup_async(self, username, callback):
                callback(None)

        invocation = self.call(self.make_agent(Store()))
        self.assertEqual(invocation.error[0], "org.freedesktop.NetworkManager.SecretAgent.NoSecrets")


class AsyncLookupTimeoutTests(unittest.TestCase):
    def test_memory_hit_and_timeout(self):
        from unittest import mock

        from pervius import credentials

        store = credentials.CredentialStore()
        store.remember("vpn@example", "pw")
        got = []
        store.lookup_async("vpn@example", got.append)
        loop = GLib.MainContext.default()
        while loop.pending():
            loop.iteration(False)
        self.assertEqual(got, ["pw"])

        if not store.persistence_available:
            self.skipTest("libsecret schema unavailable")
        with mock.patch.object(credentials.Secret, "password_lookup", lambda *a, **k: None):
            store.lookup_async("other@example", got.append, timeout=1)
            main = GLib.MainLoop()
            GLib.timeout_add(2600, main.quit)  # seconds timers may fire up to ~1 s late
            main.run()
        self.assertEqual(got, ["pw", None])


if __name__ == "__main__":
    unittest.main()
