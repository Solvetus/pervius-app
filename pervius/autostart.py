"""Start at login through an XDG autostart entry.

The entry lives in ``$XDG_CONFIG_HOME/autostart`` and starts Pervius hidden
in the tray.  Its existence is the setting: turning the option off removes
the file.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .config import APP_ID, APP_NAME

ENTRY = f"""[Desktop Entry]
Type=Application
Name={APP_NAME}
Exec=pervius --hidden
Icon={APP_ID}
Terminal=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
"""


def autostart_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base).expanduser() / "autostart" / f"{APP_ID}.desktop"


def is_enabled() -> bool:
    return autostart_path().is_file()


def set_enabled(enabled: bool) -> None:
    path = autostart_path()
    if enabled:
        # The autostart directory is shared with other applications: create it
        # if needed but never change its mode.
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "wb") as handle:
                handle.write(ENTRY.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
