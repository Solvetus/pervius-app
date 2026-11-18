"""Upgrade migration from the pre-rename 0.1.x releases."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from pervius import migration  # noqa: E402
from pervius.config import (  # noqa: E402
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
    certificate_dir,
    user_data_dir,
)
from pervius.migration import (  # noqa: E402
    DEFERRED,
    DONE,
    LEGACY_APP_SLUG,
    LEGACY_CONNECTION_ID,
    REFUSED,
    SKIPPED,
    KeyringError,
    MigrationState,
)
from pervius.nm.importer import _normalize_pem  # noqa: E402
from pervius.ownership import (  # noqa: E402
    OwnershipError,
    OwnershipStore,
    find_managed_connection,
)
from pervius.settings import SettingsStore  # noqa: E402
from tests.fixtures import CA_PEM  # noqa: E402

USER = "tester"
CA_NAME = "ca-0123456789abcdef.pem"
CA_SHA256 = hashlib.sha256(_normalize_pem(CA_PEM).encode()).hexdigest()


class SandboxMixin:
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.home = Path(self._temp.name)
        patcher = mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._temp.cleanup)
        self.old = self.home / LEGACY_APP_SLUG
        self.new = user_data_dir()

    def write_legacy(self, *, settings=True, manifest=True, ca=True, catalogue=True):
        self.old.mkdir(mode=0o700)
        if settings:
            (self.old / "settings.json").write_text(json.dumps({
                "username": "vpnuser@example",
                "location_key": "PT/Lisbon",
                "protocol": "tcp",
                "favorites": ["PT/Lisbon", "ES/Madrid"],
                "notifications_enabled": False,
            }))
        if catalogue:
            (self.old / "catalogue").mkdir()
            (self.old / "catalogue" / "last-known-good.zip").write_bytes(b"PK-zip")
            (self.old / "catalogue" / "last-known-good.json").write_text("{}")
        old_ca = self.old / "certificates" / "nm-openvpn" / CA_NAME
        if ca:
            old_ca.parent.mkdir(parents=True)
            old_ca.write_text(CA_PEM)
            old_ca.chmod(0o600)
        if manifest:
            (self.old / "ownership.json").write_text(json.dumps({
                "format": 1,
                "profiles": {
                    MANAGED_UUID: {
                        "connection_id": LEGACY_CONNECTION_ID,
                        "service_type": OPENVPN_SERVICE_TYPE,
                        "created_at": "2026-11-17T00:00:00+00:00",
                        "updated_at": "2026-11-17T00:00:00+00:00",
                        "source_sha256": "a" * 64,
                        "ca_sha256": CA_SHA256,
                        "ca_path": str(old_ca),
                    }
                },
            }))
        return old_ca


# ------------------------------------------------------------------- files


class FileMigrationTests(SandboxMixin, unittest.TestCase):
    def test_no_previous_install_is_a_no_op(self):
        self.assertEqual(migration.migrate_files().status, SKIPPED)
        self.assertFalse(self.new.exists())

    def test_copies_settings_favorites_manifest_catalogue_and_ca(self):
        self.write_legacy()
        self.assertEqual(migration.migrate_files().status, DONE)
        settings = SettingsStore().load()
        self.assertEqual(settings.favorites, ["PT/Lisbon", "ES/Madrid"])
        self.assertEqual(settings.location_key, "PT/Lisbon")
        self.assertEqual(settings.protocol, "tcp")
        self.assertFalse(settings.notifications_enabled)
        self.assertTrue((self.new / "ownership.json").is_file())
        self.assertEqual((self.new / "catalogue" / "last-known-good.zip").read_bytes(), b"PK-zip")
        new_ca = certificate_dir() / CA_NAME
        self.assertEqual(new_ca.read_text(), CA_PEM)
        for path in (self.new / "settings.json", new_ca, self.new / "ownership.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
        for path in (self.new, self.new / "catalogue", certificate_dir(), certificate_dir().parent):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700, path)
        # The previous directory is left untouched.
        self.assertTrue((self.old / "settings.json").is_file())
        self.assertTrue(MigrationState().done("files"))

    def test_runs_once(self):
        self.write_legacy()
        migration.migrate_files()
        (self.new / "settings.json").write_text('{"protocol": "udp"}')
        (self.old / "settings.json").write_text('{"protocol": "tcp", "favorites": ["X/Y"]}')
        self.assertEqual(migration.migrate_files().status, DONE)
        self.assertEqual(SettingsStore().load().protocol, "udp")

    def test_existing_new_files_are_not_overwritten(self):
        self.write_legacy()
        self.new.mkdir(parents=True)
        (self.new / "settings.json").write_text('{"protocol": "udp", "favorites": ["JP/Tokyo"]}')
        migration.migrate_files()
        self.assertEqual(SettingsStore().load().favorites, ["JP/Tokyo"])

    def test_symlinks_are_never_followed(self):
        self.write_legacy(settings=False)
        secret = self.home / "elsewhere.txt"
        secret.write_text("not ours")
        (self.old / "settings.json").symlink_to(secret)
        (self.old / "certificates" / "nm-openvpn" / "link.pem").symlink_to(secret)
        migration.migrate_files()
        self.assertFalse((self.new / "settings.json").exists())
        self.assertFalse((certificate_dir() / "link.pem").exists())

    def test_symlinked_previous_directory_is_ignored(self):
        real = self.home / "real"
        real.mkdir()
        (real / "settings.json").write_text("{}")
        self.old.symlink_to(real)
        self.assertEqual(migration.migrate_files().status, SKIPPED)
        self.assertFalse(self.new.exists())

    def test_oversized_files_are_skipped(self):
        self.write_legacy()
        with mock.patch.object(migration, "MAX_COPY_BYTES", 4):
            migration.migrate_files()
        self.assertFalse((self.new / "settings.json").exists())


# ----------------------------------------------------------------- keyring


class FakeKeyring:
    def __init__(self, legacy=None, new=None):
        self.legacy = dict(legacy or {})
        self.new = dict(new or {})
        self.fail_store = False
        self.corrupt_store = False
        self.unavailable = False

    def legacy_entries(self):
        if self.unavailable:
            raise KeyringError("keyring is locked")
        return sorted(self.legacy.items())

    def lookup(self, username):
        return self.new.get(username)

    def store(self, username, password):
        if self.fail_store:
            raise KeyringError("write refused")
        self.new[username] = "corrupted" if self.corrupt_store else password

    def clear_legacy(self, username):
        self.legacy.pop(username, None)


class KeyringMigrationTests(SandboxMixin, unittest.TestCase):
    SECRET = "s3cret-Value-42"

    def setUp(self):
        super().setUp()
        self.write_legacy()

    def test_no_previous_install_leaves_keyring_alone(self):
        for path in sorted(self.old.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        self.old.rmdir()
        keyring = FakeKeyring({"vpnuser": self.SECRET})
        self.assertEqual(migration.migrate_keyring(keyring).status, SKIPPED)
        self.assertEqual(keyring.legacy, {"vpnuser": self.SECRET})

    def test_copies_verifies_then_deletes_old_entries(self):
        keyring = FakeKeyring({"vpnuser": self.SECRET, "second": "other-secret"})
        self.assertEqual(migration.migrate_keyring(keyring).status, DONE)
        self.assertEqual(keyring.new, {"vpnuser": self.SECRET, "second": "other-secret"})
        self.assertEqual(keyring.legacy, {})
        self.assertTrue(MigrationState().done("keyring"))
        # Done is recorded: later runs do not touch the keyring again.
        keyring.legacy = {"vpnuser": "late"}
        self.assertEqual(migration.migrate_keyring(keyring).status, DONE)
        self.assertEqual(keyring.legacy, {"vpnuser": "late"})

    def test_existing_new_entry_wins_and_old_entry_is_removed(self):
        keyring = FakeKeyring({"vpnuser": "old"}, {"vpnuser": "newer"})
        migration.migrate_keyring(keyring)
        self.assertEqual(keyring.new, {"vpnuser": "newer"})
        self.assertEqual(keyring.legacy, {})

    def test_store_failure_keeps_the_old_entry_and_retries_later(self):
        keyring = FakeKeyring({"vpnuser": self.SECRET})
        keyring.fail_store = True
        self.assertEqual(migration.migrate_keyring(keyring).status, DEFERRED)
        self.assertEqual(keyring.legacy, {"vpnuser": self.SECRET})
        self.assertFalse(MigrationState().done("keyring"))

    def test_unverified_copy_keeps_the_old_entry(self):
        keyring = FakeKeyring({"vpnuser": self.SECRET})
        keyring.corrupt_store = True
        self.assertEqual(migration.migrate_keyring(keyring).status, DEFERRED)
        self.assertEqual(keyring.legacy, {"vpnuser": self.SECRET})

    def test_locked_keyring_is_deferred(self):
        keyring = FakeKeyring({"vpnuser": self.SECRET})
        keyring.unavailable = True
        self.assertEqual(migration.migrate_keyring(keyring).status, DEFERRED)
        self.assertEqual(keyring.legacy, {"vpnuser": self.SECRET})

    def test_secrets_and_usernames_never_reach_the_log(self):
        failing = FakeKeyring({"vpnuser": self.SECRET})
        failing.fail_store = True
        with self.assertLogs("pervius.migration", level="DEBUG") as captured_failure:
            self.assertEqual(migration.migrate_keyring(failing).status, DEFERRED)
        keyring = FakeKeyring({"vpnuser": self.SECRET})
        with self.assertLogs("pervius.migration", level="DEBUG") as captured:
            self.assertEqual(migration.migrate_keyring(keyring).status, DONE)
        text = "\n".join(captured.output + captured_failure.output)
        self.assertNotIn(self.SECRET, text)
        self.assertNotIn("vpnuser", text)


# ----------------------------------------------------------------- profile


def make_connection(*, connection_id=LEGACY_CONNECTION_ID, ca_path="", owner=USER, uuid=MANAGED_UUID):
    connection = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.props.id = connection_id
    s_con.props.uuid = uuid
    s_con.props.type = "vpn"
    if owner:
        s_con.add_permission("user", owner, None)
    s_vpn = NM.SettingVpn.new()
    s_vpn.props.service_type = OPENVPN_SERVICE_TYPE
    s_vpn.add_data_item("remote", "vpn0.example.com:1194")
    s_vpn.add_data_item("connection-type", "password")
    s_vpn.add_data_item("username", "vpnuser@example")
    s_vpn.add_data_item("password-flags", str(int(NM.SettingSecretFlags.AGENT_OWNED)))
    if ca_path:
        s_vpn.add_data_item("ca", ca_path)
    connection.add_setting(s_con)
    connection.add_setting(s_vpn)
    return connection


class ProfileMigrationTests(SandboxMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.old_ca = self.write_legacy()
        migration.migrate_files()
        self.updates = []

    def update(self, connection, variant):
        self.updates.append((connection, NM.SimpleConnection.new_from_dbus(variant)))

    def run_migration(self, connections):
        return migration.migrate_profile(connections, USER, update=self.update)

    def test_owned_profile_is_renamed_and_points_at_the_copied_ca(self):
        connection = make_connection(ca_path=str(self.old_ca))
        result = self.run_migration([connection])
        self.assertEqual(result.status, DONE, result.detail)
        self.assertEqual(len(self.updates), 1)
        updated = self.updates[0][1]
        self.assertEqual(updated.get_setting_connection().get_id(), MANAGED_CONNECTION_ID)
        self.assertEqual(updated.get_setting_connection().get_uuid(), MANAGED_UUID)
        new_ca = str(certificate_dir() / CA_NAME)
        self.assertEqual(updated.get_setting_vpn().get_data_item("ca"), new_ca)
        self.assertEqual(list(updated.get_setting_connection().props.permissions), ["user:tester:"])
        entry = OwnershipStore.load().get()
        self.assertEqual((entry.connection_id, entry.ca_path), (MANAGED_CONNECTION_ID, new_ca))
        self.assertEqual(entry.created_at, "2026-11-17T00:00:00+00:00")
        # The renamed profile now passes the strict, unchanged ownership check.
        lookup = find_managed_connection([updated], OwnershipStore.load(), USER)
        self.assertIs(lookup.connection, updated)
        self.assertTrue(MigrationState().done("profile"))

    def test_legacy_id_is_rejected_outside_the_migration(self):
        connection = make_connection(ca_path=str(self.old_ca))
        with self.assertRaises(OwnershipError):
            find_managed_connection([connection], OwnershipStore.load(), USER)

    def test_profile_owned_by_someone_else_is_left_untouched(self):
        connection = make_connection(ca_path=str(self.old_ca), owner="mallory")
        result = self.run_migration([connection])
        self.assertEqual(result.status, REFUSED)
        self.assertEqual(self.updates, [])
        self.assertEqual(OwnershipStore.load().get().connection_id, LEGACY_CONNECTION_ID)
        self.assertFalse(MigrationState().done("profile"))

    def test_unrestricted_profile_is_left_untouched(self):
        result = self.run_migration([make_connection(ca_path=str(self.old_ca), owner="")])
        self.assertEqual(result.status, REFUSED)
        self.assertEqual(self.updates, [])

    def test_ca_hash_mismatch_is_refused(self):
        (certificate_dir() / CA_NAME).write_text(CA_PEM.replace("AAAA", "BBBB"))
        result = self.run_migration([make_connection(ca_path=str(self.old_ca))])
        self.assertEqual(result.status, REFUSED)
        self.assertIn("CA", result.detail)
        self.assertEqual(self.updates, [])

    def test_profile_with_foreign_ca_path_is_refused(self):
        result = self.run_migration([make_connection(ca_path="/etc/ssl/certs/other.pem")])
        self.assertEqual(result.status, REFUSED)
        self.assertEqual(self.updates, [])

    def test_ambiguous_profiles_are_refused(self):
        first = make_connection(ca_path=str(self.old_ca))
        second = make_connection(ca_path=str(self.old_ca), uuid="5b0c7a7e-0000-4000-8000-000000000001")
        result = self.run_migration([first, second])
        self.assertEqual(result.status, REFUSED)
        self.assertEqual(self.updates, [])

    def test_already_renamed_profile_only_repairs_the_manifest(self):
        new_ca = str(certificate_dir() / CA_NAME)
        connection = make_connection(connection_id=MANAGED_CONNECTION_ID, ca_path=new_ca)
        result = self.run_migration([connection])
        self.assertEqual(result.status, DONE, result.detail)
        self.assertEqual(self.updates, [])
        self.assertEqual(OwnershipStore.load().get().connection_id, MANAGED_CONNECTION_ID)

    def test_deleted_profile_only_updates_the_manifest(self):
        self.assertEqual(self.run_migration([]).status, DONE)
        self.assertEqual(self.updates, [])
        entry = OwnershipStore.load().get()
        self.assertEqual(entry.connection_id, MANAGED_CONNECTION_ID)
        self.assertEqual(entry.ca_path, str(certificate_dir() / CA_NAME))

    def test_networkmanager_rejection_is_reported_and_retried(self):
        def reject(_connection, _variant):
            raise RuntimeError("not authorized")

        result = migration.migrate_profile([make_connection(ca_path=str(self.old_ca))], USER, update=reject)
        self.assertEqual(result.status, REFUSED)
        self.assertIn("not authorized", result.detail)
        self.assertEqual(OwnershipStore.load().get().connection_id, LEGACY_CONNECTION_ID)
        self.assertFalse(MigrationState().done("profile"))

    def test_no_previous_manifest_means_nothing_to_adopt(self):
        (self.new / "ownership.json").unlink()
        self.assertEqual(self.run_migration([]).status, DONE)

    def test_waits_for_the_file_step(self):
        state_path = self.new / migration.STATE_NAME
        state_path.unlink()
        result = self.run_migration([make_connection(ca_path=str(self.old_ca))])
        self.assertEqual(result.status, DEFERRED)
        self.assertEqual(self.updates, [])

    def test_runs_once(self):
        self.run_migration([make_connection(ca_path=str(self.old_ca))])
        self.updates.clear()
        self.assertEqual(self.run_migration([make_connection(ca_path=str(self.old_ca))]).status, DONE)
        self.assertEqual(self.updates, [])


class DriverTests(SandboxMixin, unittest.TestCase):
    def test_fresh_install_writes_nothing(self):
        with mock.patch.object(migration, "migrate_keyring") as keyring:
            migration.migrate_user_data()
        keyring.assert_not_called()
        self.assertFalse(self.new.exists())

    def test_upgrade_runs_files_then_keyring(self):
        self.write_legacy()
        with mock.patch.object(migration, "migrate_keyring") as keyring:
            migration.migrate_user_data()
        keyring.assert_called_once_with()
        self.assertTrue((self.new / "settings.json").is_file())


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
