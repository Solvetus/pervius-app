from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from pervius.config import MANAGED_CONNECTION_ID, MANAGED_UUID, OPENVPN_SERVICE_TYPE  # noqa: E402
from pervius.ownership import (  # noqa: E402
    OwnershipEntry,
    OwnershipError,
    OwnershipStore,
    check_create_collision,
    connection_is_owned,
    find_managed_connection,
)

USER = "tester"


def make_connection(
    *,
    uuid: str = MANAGED_UUID,
    connection_id: str = MANAGED_CONNECTION_ID,
    service: str = OPENVPN_SERVICE_TYPE,
    username: str = USER,
    restricted: bool = True,
) -> NM.SimpleConnection:
    connection = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.props.id = connection_id
    s_con.props.uuid = uuid
    s_con.props.type = "vpn"
    if restricted:
        s_con.add_permission("user", username, None)
    s_vpn = NM.SettingVpn.new()
    s_vpn.props.service_type = service
    connection.add_setting(s_con)
    connection.add_setting(s_vpn)
    return connection


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.path = Path(self._temp.name) / "ownership.json"

    def tearDown(self):
        self._temp.cleanup()

    def test_missing_manifest_with_no_collision_is_safe(self):
        store = OwnershipStore.load(self.path)
        lookup = find_managed_connection([], store, USER)
        self.assertIsNone(lookup.connection)
        self.assertIsNone(lookup.entry)
        self.assertFalse(lookup.stale_entry)

    def test_reserved_connection_without_manifest_is_rejected(self):
        store = OwnershipStore.load(self.path)
        with self.assertRaisesRegex(OwnershipError, "no matching entry"):
            find_managed_connection([make_connection()], store, USER)

    def test_stale_manifest_is_reported(self):
        store = OwnershipStore.load(self.path)
        store.record(OwnershipEntry())
        lookup = find_managed_connection([], store, USER)
        self.assertIsNone(lookup.connection)
        self.assertTrue(lookup.stale_entry)

    def test_owned_connection_is_found(self):
        store = OwnershipStore.load(self.path)
        store.record(OwnershipEntry())
        connection = make_connection()
        lookup = find_managed_connection([connection], store, USER)
        self.assertIs(lookup.connection, connection)
        self.assertTrue(lookup.entry is not None)

    def test_wrong_permissions_are_rejected(self):
        store = OwnershipStore.load(self.path)
        store.record(OwnershipEntry())
        connection = make_connection(username="someone-else")
        with self.assertRaisesRegex(OwnershipError, "not restricted to the current user"):
            find_managed_connection([connection], store, USER)

    def test_unrestricted_connection_is_rejected(self):
        store = OwnershipStore.load(self.path)
        store.record(OwnershipEntry())
        connection = make_connection(restricted=False)
        with self.assertRaisesRegex(OwnershipError, "not restricted"):
            find_managed_connection([connection], store, USER)

    def test_wrong_service_is_rejected(self):
        store = OwnershipStore.load(self.path)
        store.record(OwnershipEntry())
        connection = make_connection(service="org.example.other")
        with self.assertRaisesRegex(OwnershipError, "not restricted|does not match"):
            find_managed_connection([connection], store, USER)

    def test_id_collision_and_uuid_collision_are_ambiguous(self):
        store = OwnershipStore.load(self.path)
        store.record(OwnershipEntry())
        by_id = make_connection(uuid="11111111-1111-1111-1111-111111111111")
        by_uuid = make_connection(connection_id="Something Else")
        with self.assertRaisesRegex(OwnershipError, "multiple connections"):
            find_managed_connection([by_id, by_uuid], store, USER)

    def test_manifest_with_wrong_reserved_ids_is_rejected(self):
        store = OwnershipStore.load(self.path)
        store.record(OwnershipEntry(uuid="11111111-1111-1111-1111-111111111111"))
        with self.assertRaisesRegex(OwnershipError, "other than the reserved"):
            find_managed_connection([], store, USER)

    def test_create_collision_detects_id(self):
        with self.assertRaisesRegex(OwnershipError, "already in use"):
            check_create_collision(
                [make_connection(uuid="11111111-1111-1111-1111-111111111111")],
                USER,
            )

    def test_create_collision_detects_uuid(self):
        with self.assertRaisesRegex(OwnershipError, "already in use"):
            check_create_collision(
                [make_connection(connection_id="Something Else")],
                USER,
            )

    def test_create_collision_allows_unrelated(self):
        check_create_collision(
            [make_connection(uuid="11111111-1111-1111-1111-111111111111", connection_id="Other")],
            USER,
        )

    def test_manifest_round_trip(self):
        store = OwnershipStore.load(self.path)
        entry = OwnershipEntry(
            source_sha256="a" * 64,
            ca_sha256="b" * 64,
            ca_path="/tmp/ca.pem",
        )
        store.record(entry)
        loaded = OwnershipStore.load(self.path).get()
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.source_sha256, "a" * 64)
        self.assertEqual(loaded.ca_path, "/tmp/ca.pem")
        self.assertTrue(loaded.created_at)
        self.assertTrue(loaded.updated_at)

    def test_manifest_remove(self):
        store = OwnershipStore.load(self.path)
        store.record(OwnershipEntry())
        store.remove()
        self.assertIsNone(OwnershipStore.load(self.path).get())

    def test_malformed_manifest_is_rejected(self):
        self.path.write_text('{"format": 1, "profiles": []}', encoding="utf-8")
        with self.assertRaisesRegex(OwnershipError, "missing its profiles map"):
            OwnershipStore.load(self.path)

    def test_connection_is_owned_requires_username(self):
        entry = OwnershipEntry()
        self.assertFalse(connection_is_owned(make_connection(), entry, ""))


if __name__ == "__main__":
    unittest.main()
