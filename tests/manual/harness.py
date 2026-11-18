"""Shared helpers for the manual Broadway UI harnesses.

The harnesses drive the real GTK window against a private Broadway display.
They never touch the real NetworkManager profile, keyring, or kill-switch
service:

* the NetworkManager secret agent is not registered (register() is stubbed);
* the kill-switch client always reports a disarmed service;
* the public-IP lookup returns a documentation address (RFC 5737);
* a synthetic catalogue (example.com hosts) is seeded into a sandboxed
  XDG_DATA_HOME, which must be a temporary directory (run.sh creates one).

Each harness records checks with ``Checks`` and exits non-zero on failure.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

DOC_IP = "198.51.100.7"

# Real city names, synthetic profiles: every remote is an example.com host.
LOCATIONS = (
    ("AD", "Andorra la Vella"),
    ("ES", "Madrid"),
    ("GB", "Belfast"),
    ("GB", "London"),
    ("JP", "Tokyo"),
    ("PT", "Lisbon"),
    ("US", "Ashburn"),
    ("US", "New York"),
)


def require_sandbox() -> Path:
    """Refuse to run unless XDG_DATA_HOME points inside the temp directory."""
    value = os.environ.get("XDG_DATA_HOME", "")
    tmp = Path(tempfile.gettempdir()).resolve()
    if not value:
        raise SystemExit("refusing to run: XDG_DATA_HOME is not set (use tests/manual/run.sh)")
    path = Path(value).resolve()
    if tmp not in path.parents:
        raise SystemExit(f"refusing to run: XDG_DATA_HOME must be under {tmp}")
    return path


def synthetic_catalogue_zip() -> bytes:
    from tests.fixtures import profile_text, zip_with

    entries = {}
    for index, (country, city) in enumerate(LOCATIONS):
        for protocol in ("udp", "tcp"):
            name = f"{protocol}/NCVPN-{country}-{city}-{protocol.upper()}.ovpn"
            entries[name] = profile_text(
                protocol=protocol, host=f"vpn{index}.example.com"
            ).encode()
    return zip_with(entries)


def seed_catalogue() -> None:
    from pervius.catalogue import CatalogueStore, parse_catalogue

    blob = synthetic_catalogue_zip()
    CatalogueStore().save(blob, parse_catalogue(blob, source_url="https://example.com/catalogue.zip"))


def install_stubs() -> None:
    """Keep the harness away from privileged or external services."""
    from pervius import killswitch_client
    from pervius.nm.agent import NetworkManagerSecretAgent
    from pervius.ui import window as window_module

    def fake_register(self):
        self._registered = True

    NetworkManagerSecretAgent.register = fake_register
    NetworkManagerSecretAgent.unregister = lambda self: setattr(self, "_registered", False)
    killswitch_client.KillSwitchClient.status = lambda self: {
        "armed": False,
        "state": "off",
        "detail": "Not armed",
        "endpoints": 0,
        "allow_lan": False,
    }
    window_module.fetch_public_ip = lambda: DOC_IP
    window_module.fetch_public_ip_through = lambda _interface: DOC_IP


def prepare(*, catalogue: bool = True) -> None:
    require_sandbox()
    install_stubs()
    if catalogue:
        seed_catalogue()


class Checks:
    def __init__(self, name: str):
        self.name = name
        self.failures: list[str] = []
        self.count = 0

    def equal(self, label: str, actual, expected) -> None:
        self.count += 1
        if actual == expected:
            print(f"ok   {label}: {actual!r}", flush=True)
        else:
            message = f"{label}: expected {expected!r}, got {actual!r}"
            self.failures.append(message)
            print(f"FAIL {message}", flush=True)

    def true(self, label: str, value) -> None:
        self.equal(label, bool(value), True)

    def exit_code(self) -> int:
        status = "PASS" if not self.failures else "FAIL"
        print(f"{status} {self.name}: {self.count - len(self.failures)}/{self.count} checks", flush=True)
        return 1 if self.failures else 0


def run_window_harness(name: str, scenario, *, delay_ms: int = 2000, catalogue: bool = True) -> int:
    """Open MainWindow in a non-unique app and run *scenario(window, checks, done)*.

    The scenario calls ``done()`` when finished; the harness then cleans up and
    exits with the check result.
    """
    prepare(catalogue=catalogue)

    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gio, GLib, Gtk

    from pervius.ui.window import MainWindow

    checks = Checks(name)

    class Harness(Adw.Application):
        def __init__(self):
            super().__init__(
                application_id="org.example.UiHarness",
                flags=Gio.ApplicationFlags.NON_UNIQUE,
            )
            self.window = None

        def do_activate(self):
            self.window = MainWindow(application=self)
            # Record every toast so scenarios can check its text and timeout.
            self.window.recorded_toasts = []
            original = self.window.toasts.add_toast

            def add_toast(toast):
                self.window.recorded_toasts.append(toast)
                original(toast)

            self.window.toasts.add_toast = add_toast
            self.window.present()
            GLib.timeout_add(delay_ms, self._run)

        def _run(self):
            try:
                scenario(self.window, checks, self._done)
            except Exception as exc:  # report and stop instead of hanging
                checks.failures.append(f"scenario raised {type(exc).__name__}: {exc}")
                print(f"FAIL scenario raised {type(exc).__name__}: {exc}", flush=True)
                self._done()
            return False

        def _done(self):
            if self.window is not None:
                self.window.cleanup()
            self.quit()
            return False

    Gtk.init()
    Adw.init()
    Harness().run([])
    return checks.exit_code()
