"""Every user-visible string is marked for translation.

An AST scan of the UI modules flags any string literal that looks like human
text (a letter followed later by a space, or a capitalised word) unless it
is the argument of a gettext call (_, N_, C_, ngettext), a docstring, a log
message, or in the small allowlist below (product names, protocol names,
endonyms and identifiers).
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCANNED = sorted((REPO / "pervius" / "ui").glob("*.py"))
GETTEXT = {"_", "N_", "C_", "ngettext", "pgettext"}
LOGGING = {"debug", "info", "warning", "error", "exception", "critical"}
# Calls whose string arguments are identifiers, protocol data or internal
# diagnostics, never text a user reads.
TECHNICAL = {
    "require_version",
    "getattr",
    "emit_signal",
    "call_sync",
    "signal_subscribe",
    "return_dbus_error",
    "Variant",
    "VariantType",
    "new_for_xml",
    "add_response",  # first argument is a response id; labels are checked below
    "set_response_appearance",
    "set_close_response",
    "set_default_response",
    "set_visible_child_name",
    "add_named",
    "add_css_class",
    "remove_css_class",
    "write",  # sys.stderr.write before the UI starts (command-line output)
}

# Literals that are shown but must not be translated.
ALLOWED = {
    "OpenVPN",
    "OpenVPN ·",
    "UDP",
    "TCP",
    "VPN",
    "—",
    "English",
    "Português",
    "Français",
    "Español",
    "Italiano",
    "© 2026 Solvetus Labs",
    "pervius-killswitch disarm",
}
HUMAN = re.compile(r"[A-Za-zÀ-ÿ]{2,}[^\n]*\s+[A-Za-zÀ-ÿ]|^[A-Z][a-z]{2,}")
IDENTIFIER = re.compile(r"^[a-z0-9_.:|/-]+(-symbolic)?$|^[a-z-]+::[a-z-]+$|^[A-Za-z0-9_.-]+\.(svg|py)$")


class _Visitor(ast.NodeVisitor):
    def __init__(self):
        self.exempt: set[int] = set()
        self.found: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call):
        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        target = ast.unparse(node.func)
        if name in GETTEXT or (name in LOGGING and target.startswith(("log.", "logging."))):
            for child in ast.walk(node):
                self.exempt.add(id(child))
        elif name == "add_response":
            # add_response(id, label): only the label is shown.
            if node.args:
                self.exempt.add(id(node.args[0]))
        elif name in TECHNICAL or name.endswith(("Error", "Exception")):
            for child in node.args:
                for grandchild in ast.walk(child):
                    self.exempt.add(id(grandchild))
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            self.exempt.add(id(node.value))  # docstring or bare string
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        for child in ast.walk(node):
            self.exempt.add(id(child))  # comparisons against state names
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        for child in ast.walk(node.slice):
            self.exempt.add(id(child))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.found.append((node.lineno, node.value, id(node)))


def untranslated(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    visitor = _Visitor()
    visitor.visit(tree)
    problems = []
    for lineno, value, node_id in visitor.found:
        if node_id in visitor.exempt:
            continue
        text = value.strip()
        if (
            not text
            or text in ALLOWED
            or IDENTIFIER.match(text)
            or text.startswith("<node>")
            or "headerbar." in text  # the stylesheet, not UI text
            or text.startswith("px; }")
        ):
            continue
        if not HUMAN.search(text):
            continue
        problems.append(f"{path.name}:{lineno}: {value!r}")
    return problems


class TranslationCoverageTests(unittest.TestCase):
    def test_visible_strings_are_wrapped(self):
        problems = [item for path in SCANNED for item in untranslated(path)]
        self.assertEqual(problems, [], "\n".join(problems))

    def test_the_scanner_catches_an_unwrapped_string(self):
        sample = Path(self.id().replace(".", "_") + ".py")
        tmp = REPO / "build" / "i18n-scan"
        tmp.mkdir(parents=True, exist_ok=True)
        probe = tmp / sample.name
        probe.write_text(
            'from pervius.i18n import _\n'
            'label.set_label("Not connected")\n'
            'label.set_label(_("Connected"))\n'
            'log.info("not shown to users")\n'
            'button.set_icon_name("open-menu-symbolic")\n'
        )
        try:
            self.assertEqual(untranslated(probe), [f"{probe.name}:2: 'Not connected'"])
        finally:
            probe.unlink()


if __name__ == "__main__":
    unittest.main()
