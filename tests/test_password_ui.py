"""A stored password never reaches the user interface.

The secret agent is the only reader of a stored password (and only when
NetworkManager asks); the UI learns only whether one exists.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from pervius.credentials import SAVED_IN_KEYRING, SESSION_ONLY
from pervius.ui.account import account_view

REPO = Path(__file__).resolve().parents[1]

# Modules allowed to call CredentialStore.lookup (or the Secret lookup API).
LOOKUP_ALLOWED = {
    "pervius/credentials.py",  # the store itself
    "pervius/nm/agent.py",  # GetSecrets, after authorization
}


def python_files():
    for path in sorted((REPO / "pervius").rglob("*.py")):
        yield path, str(path.relative_to(REPO))


def calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            yield node


class FakeStore:
    """Records every call; lookup() must never be reached from the UI."""

    persistence_available = True

    def __init__(self, state):
        self.state = state
        self.lookups = 0

    def password_state(self, _username):
        return self.state

    def lookup(self, _username):
        self.lookups += 1
        raise AssertionError("the UI must never read a stored password")


class StaticTests(unittest.TestCase):
    def test_only_the_agent_and_the_store_read_passwords(self):
        offenders = []
        for path, rel in python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in calls(tree):
                if node.func.attr in {"lookup", "password_lookup_sync", "password_lookup"}:
                    if rel not in LOOKUP_ALLOWED:
                        offenders.append(f"{rel}:{node.lineno}")
        self.assertEqual(offenders, [])

    def test_ui_never_fills_a_password_widget(self):
        offenders = []
        for path in sorted((REPO / "pervius" / "ui").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in calls(tree):
                if node.func.attr != "set_text":
                    continue
                target = ast.unparse(node.func.value).lower()
                if "password" not in target:
                    continue
                literal_empty = (
                    len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == ""
                )
                if not literal_empty:
                    offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(offenders, [])

    def test_ui_has_no_reveal_of_stored_secrets(self):
        # The only password widget is Adw.PasswordEntryRow, whose reveal toggle
        # applies to the text typed into it; no other reveal mechanism exists.
        for path in sorted((REPO / "pervius" / "ui").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("set_show_peek_icon", text, path.name)
            self.assertNotIn("set_visibility", text, path.name)

    def test_window_wires_the_agent_to_the_store_not_to_a_password(self):
        tree = ast.parse((REPO / "pervius/ui/window.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "NetworkManagerSecretAgent":
                first = node.args[0]
                self.assertEqual(ast.unparse(first), "self.credentials")
                break
        else:
            self.fail("secret agent construction not found")


class AccountViewTests(unittest.TestCase):
    def test_saved_password_shows_status_not_entry(self):
        store = FakeStore(SAVED_IN_KEYRING)
        view = account_view(store, "user@example", "user@example")
        self.assertEqual(view.kept, SAVED_IN_KEYRING)
        self.assertFalse(view.show_entry)
        self.assertTrue(view.can_forget)
        self.assertEqual(store.lookups, 0)

    def test_session_password_shows_status(self):
        view = account_view(FakeStore(SESSION_ONLY), "user@example", "user@example")
        self.assertEqual(view.kept, SESSION_ONLY)
        self.assertFalse(view.show_entry)

    def test_no_password_shows_empty_entry(self):
        view = account_view(FakeStore(None), "user@example", "user@example")
        self.assertTrue(view.show_entry)
        self.assertFalse(view.can_forget)

    def test_new_username_requires_a_new_password(self):
        view = account_view(FakeStore(SAVED_IN_KEYRING), "user@example", "other@example")
        self.assertTrue(view.show_entry)
        self.assertIsNone(view.kept)

    def test_no_username(self):
        view = account_view(FakeStore(SAVED_IN_KEYRING), "", "")
        self.assertTrue(view.show_entry)
        self.assertFalse(view.can_forget)


class AgentIsTheOnlyReaderTests(unittest.TestCase):
    def test_agent_reads_the_store_for_the_configured_account(self):
        from pervius.nm.agent import NetworkManagerSecretAgent

        class Store:
            def __init__(self):
                self.asked = []

            def lookup(self, username):
                self.asked.append(username)
                return "secret"

        store = Store()
        agent = NetworkManagerSecretAgent(store, lambda: " vpn@example ", username="tester")
        self.assertEqual(agent._lookup_password(), "secret")
        self.assertEqual(store.asked, ["vpn@example"])

    def test_agent_without_username_reads_nothing(self):
        from pervius.nm.agent import NetworkManagerSecretAgent

        class Store:
            def lookup(self, _username):
                raise AssertionError("no lookup without a username")

        agent = NetworkManagerSecretAgent(Store(), lambda: "", username="tester")
        self.assertIsNone(agent._lookup_password())


if __name__ == "__main__":
    unittest.main()


class PasswordStateTests(unittest.TestCase):
    def test_password_state_searches_without_loading_the_secret(self):
        from unittest import mock

        from pervius import credentials

        store = credentials.CredentialStore()
        if not store.persistence_available:
            self.skipTest("libsecret schema unavailable")
        with mock.patch.object(credentials.Secret, "password_search_sync", return_value=[object()]) as search, \
                mock.patch.object(credentials.Secret, "password_lookup_sync") as lookup:
            self.assertEqual(store.password_state("vpn@example"), SAVED_IN_KEYRING)
        lookup.assert_not_called()
        flags = search.call_args.args[2]
        self.assertEqual(flags, credentials.Secret.SearchFlags.NONE)

    def test_password_state_memory_only(self):
        from unittest import mock

        from pervius import credentials

        store = credentials.CredentialStore()
        store.remember("vpn@example", "pw")
        with mock.patch.object(credentials.Secret, "password_search_sync", return_value=[]):
            self.assertEqual(store.password_state("vpn@example"), SESSION_ONLY)
            self.assertIsNone(store.password_state("other@example"))
