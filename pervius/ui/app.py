"""libadwaita application shell."""

from __future__ import annotations

import logging
import os
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk  # noqa: E402

from .. import i18n  # noqa: E402
from ..config import APP_ID, APP_NAME, NOTIFICATION_ID  # noqa: E402
from ..settings import SettingsStore  # noqa: E402
from .window import MainWindow  # noqa: E402


HIDDEN_OPTION = "--hidden"


class PerviusApplication(Adw.Application):
    def __init__(self, *, start_hidden: bool = False):
        super().__init__(application_id=APP_ID, flags=0)
        self.window: MainWindow | None = None
        # Start at login runs "pervius --hidden": stay in the tray.  Without a
        # tray to come back to, show the window anyway.
        self.start_hidden = start_hidden

        present = Gio.SimpleAction.new("present", None)
        present.connect("activate", lambda *_args: self.do_activate())
        self.add_action(present)

    def do_activate(self):
        first = self.window is None
        if first:
            self.window = MainWindow(application=self)
        hidden, self.start_hidden = self.start_hidden, False
        if first and hidden and self.window.tray is not None and self.window.tray.registered:
            return
        self.withdraw_notification(NOTIFICATION_ID)
        self.window.present()

    def do_shutdown(self):
        self.withdraw_notification(NOTIFICATION_ID)
        if self.window is not None:
            self.window.cleanup()
        Adw.Application.do_shutdown(self)


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() == 0:
        sys.stderr.write(
            f"Refusing to run as root. Start {APP_NAME} as your desktop user;\n"
            "NetworkManager performs privileged network operations.\n"
        )
        return 1
    argv = list(sys.argv if argv is None else argv)
    start_hidden = HIDDEN_OPTION in argv[1:]
    argv = [argv[0], *[arg for arg in argv[1:] if arg != HIDDEN_OPTION]] if argv else argv
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(levelname)s %(message)s")
    # The language override must be in place before GTK and gettext start.
    i18n.setup(SettingsStore().load().language)
    Gtk.init()
    Adw.init()
    app = PerviusApplication(start_hidden=start_hidden)
    return app.run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
