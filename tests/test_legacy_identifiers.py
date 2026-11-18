"""The pre-rename identifiers survive only in history and migration code."""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

LEGACY = re.compile(
    r"org\.solvetus|org/solvetus|VPNManager"
    r"|solvetus[-_](?:vpn|ks|killswitch)"
    r"|/run/solvetus"
    r"|Solvetus VPN|Solvetus project"
    r"|(?<!com\.)\bsolvetus\.(?!com\b)"
    r"|\b(?:import|from) solvetus\b",
    re.IGNORECASE,
)

# Files that must mention the old identifiers.
ALLOWED = {
    "CHANGELOG.md",                     # release history
    "pervius/migration.py",             # upgrade migration
    "tests/test_migration.py",
    "packaging/debian/preinst",         # armed-kill-switch guard
    "packaging/debian/control.in",      # Conflicts/Replaces/Provides
    "tests/test_debian_preinst.py",
    "tests/test_legacy_identifiers.py",  # this file
}
SKIP_DIRS = {".git", "dist", "build", "__pycache__", ".ruff_cache", ".venv", "venv"}


def tracked_files():
    for path in sorted(REPO.rglob("*")):
        if path.is_file() and not SKIP_DIRS.intersection(path.relative_to(REPO).parts):
            yield path


class LegacyIdentifierTests(unittest.TestCase):
    def test_no_legacy_identifiers_outside_history_and_migration(self):
        hits = []
        for path in tracked_files():
            relative = str(path.relative_to(REPO))
            if relative in ALLOWED:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if LEGACY.search(line):
                    hits.append(f"{relative}:{number}: {line.strip()}")
        self.assertEqual(hits, [])

    def test_pattern_matches_legacy_and_spares_current_names(self):
        for legacy in ("org.solvetus.VPNManager", "solvetus-vpn", "inet solvetus_ks",
                       "/run/solvetus", "Solvetus VPN (managed)", "from solvetus.ui import x",
                       "solvetus-killswitch disarm", "org/solvetus/KillSwitch1"):
            self.assertRegex(legacy, LEGACY)
        for current in ("com.solvetus.Pervius", "Solvetus Labs", "info@solvetus.com",
                        "https://github.com/Solvetus/pervius-app", "com.solvetus.pervius.killswitch.control"):
            self.assertNotRegex(current, LEGACY)


if __name__ == "__main__":
    unittest.main()
