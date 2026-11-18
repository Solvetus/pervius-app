"""No blocking call runs on the GTK main thread.

The UI must stay responsive while connecting: synchronous D-Bus, keyring,
NetworkManager or kill-switch-service calls are only allowed in worker
threads (call_async) or as bounded startup calls listed here.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
UI = sorted((REPO / "pervius" / "ui").glob("*.py"))
# Bounded calls made once at startup, before the user can act: (file, function).
STARTUP_ALLOWED = {("tray.py", "_register_with_watcher"), ("tray.py", "_watcher_recognizes")}
MAX_STARTUP_TIMEOUT_MS = 5000
BLOCKING = {"call_sync", "password_lookup_sync", "password_store_sync", "password_clear_sync", "run", "sleep"}


def parents(tree):
    links = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            links[child] = node
    return links


class MainThreadTests(unittest.TestCase):
    def test_ui_has_no_synchronous_dbus_keyring_or_process_calls(self):
        offenders = []
        for path in UI:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            links = parents(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                    target = ast.unparse(node.func.value)
                    if name in BLOCKING and target not in {"app", "Harness()", "super()"}:
                        function = links.get(node)
                        while function is not None and not isinstance(function, ast.FunctionDef):
                            function = links.get(function)
                        allowed = function is not None and (path.name, function.name) in STARTUP_ALLOWED
                        timeouts = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, int)]
                        if allowed and timeouts and max(timeouts) <= MAX_STARTUP_TIMEOUT_MS:
                            continue
                        offenders.append(f"{path.name}:{node.lineno}: {ast.unparse(node.func)}")
                    if name == "lookup" and "credentials" in target:
                        offenders.append(f"{path.name}:{node.lineno}: keyring lookup")
        self.assertEqual(offenders, [])

    def test_kill_switch_service_is_only_called_from_worker_threads(self):
        tree = ast.parse((REPO / "pervius/ui/window.py").read_text(encoding="utf-8"))
        links = parents(tree)
        offenders = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and ast.unparse(node.func.value) == "self.killswitch"
            ):
                parent = links.get(node)
                while parent is not None and not isinstance(parent, ast.Lambda):
                    parent = links.get(parent)
                if parent is None:
                    offenders.append(f"window.py:{node.lineno}")
        self.assertEqual(offenders, [], "wrap service calls in call_async(lambda: ...)")

    def test_secret_agent_answers_asynchronously(self):
        text = (REPO / "pervius/nm/agent.py").read_text(encoding="utf-8")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_on_method_call":
                source = ast.unparse(node)
                self.assertNotIn(".lookup(", source)
                self.assertNotIn("password_lookup_sync", source)
                self.assertIn("_lookup_password_async", source)

    def test_every_networkmanager_call_has_a_timeout(self):
        text = (REPO / "pervius/nm/client.py").read_text(encoding="utf-8")
        for call in ("add_connection2(", "update2(", "activate_connection_async(", "deactivate_connection_async("):
            segment = text[text.index(call):text.index(call) + 400]
            self.assertIn("once.cancellable", segment, call)

    def test_kill_switch_client_calls_are_bounded(self):
        from pervius import killswitch_client

        self.assertLessEqual(killswitch_client.CALL_TIMEOUT_MS, 15000)


if __name__ == "__main__":
    unittest.main()
