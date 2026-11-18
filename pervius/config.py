"""Static configuration for Pervius.

No secret material belongs in this file or in any file derived from it.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path

from . import __version__ as VERSION

APP_ID = "com.solvetus.Pervius"
APP_NAME = "Pervius"
APP_SLUG = "pervius"
APP_TAGLINE = "Unofficial Linux client for FastVPN."
DEVELOPER_NAME = "Solvetus Labs"
HOMEPAGE_URL = "https://github.com/Solvetus/pervius-app"
ISSUES_URL = f"{HOMEPAGE_URL}/issues"
DISCLAIMER = (
    "Pervius is an independent open-source project by Solvetus Labs. It is not "
    "affiliated with, endorsed by, or sponsored by Namecheap, Inc. FastVPN is a "
    "trademark of Namecheap, Inc."
)

# Public catalogue snapshot.  The app validates the archive and every profile
# before it will import anything.  Refresh cadence is not guaranteed by the
# upstream provider.
CATALOGUE_URL = "https://vpn.ncapi.io/groupedServerList.zip"
PUBLIC_IP_URL = "https://api64.ipify.org?format=json"
USER_AGENT = f"Pervius/{VERSION} (+{HOMEPAGE_URL})"

# Resource limits, deliberately conservative.
MAX_ARCHIVE_BYTES = 5 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 1000
MAX_PROFILE_BYTES = 512 * 1024
MAX_CA_BYTES = 256 * 1024
MAX_REMOTES = 64

# One reusable, app-owned NetworkManager profile in v1.
MANAGED_CONNECTION_ID = "Pervius (managed)"
# Reserved UUID of the app-owned profile.  It is a fixed literal and must never
# change: installations upgraded from 0.1.x adopt their existing profile by it.
MANAGED_UUID = "22d97462-fd9d-5bc6-9f0b-7110f7153e4f"
MANAGED_CONNECTION_TYPE = "vpn"
# The managed profile pins the OpenVPN tunnel device to this name, so the kill
# switch and the IPv6 guard can allow exactly this interface instead of tun*.
TUNNEL_INTERFACE = "pervius0"
# NetworkManager connection user-data keys read by the IPv6 guard and the
# kill-switch service.  The dispatcher receives them as CONNECTION_USER_* vars.
USER_DATA_BLOCK_IPV6 = "com.solvetus.pervius.block-ipv6"
USER_DATA_ALLOWED_INTERFACES = "com.solvetus.pervius.allowed-interfaces"
USER_DATA_REMOTE_NAMES = "com.solvetus.pervius.remote-names"
OPENVPN_SERVICE_TYPE = "org.freedesktop.NetworkManager.openvpn"

# Tray status icons: white glyph, with a green badge when the tunnel is up and
# an amber badge while reconnecting.  The status card shows the app icon when
# connected and a grey tile otherwise.
NOTIFICATION_ID = "pervius-state"
TRAY_ICON_OFF = f"{APP_ID}-tray-off"
TRAY_ICON_CONNECTED = f"{APP_ID}-tray-connected"
TRAY_ICON_RECONNECTING = f"{APP_ID}-tray-reconnecting"
STATUS_ICON_CONNECTED = APP_ID
STATUS_ICON_OFF = f"{APP_ID}-card-off"
SYMBOLIC_ICON = f"{APP_ID}-symbolic"


def local_username() -> str:
    """Return the Unix login name of the current process.

    This is the identity used for NetworkManager profile ownership and agent
    authorization.  It is deliberately not the VPN account name.
    """
    return pwd.getpwuid(os.getuid()).pw_name

# Secret agent identity and Secret Service schema.
SECRET_AGENT_IDENTIFIER = APP_ID
SECRET_AGENT_PATH = "/org/freedesktop/NetworkManager/SecretAgent"
SECRET_AGENT_INTERFACE = "org.freedesktop.NetworkManager.SecretAgent"
AGENT_MANAGER_INTERFACE = "org.freedesktop.NetworkManager.AgentManager"
AGENT_MANAGER_PATH = "/org/freedesktop/NetworkManager/AgentManager"
SECRET_SCHEMA_NAME = APP_ID
SECRET_SCHEMA_ATTRIBUTE_USERNAME = "username"
SECRET_SCHEMA_ATTRIBUTE_PURPOSE = "purpose"
SECRET_PURPOSE = "vpn-password"


def _xdg_dir(env_name: str, fallback: str) -> Path:
    value = os.environ.get(env_name)
    if value:
        return Path(value).expanduser()
    return Path(fallback).expanduser()


def user_data_dir() -> Path:
    """Application data directory (no secrets are stored here)."""
    return _xdg_dir("XDG_DATA_HOME", str(Path.home() / ".local" / "share")) / APP_SLUG


def user_cache_dir() -> Path:
    return _xdg_dir("XDG_CACHE_HOME", str(Path.home() / ".cache")) / APP_SLUG


def runtime_dir() -> Path:
    """Private runtime staging directory.

    XDG_RUNTIME_DIR is the normal location.  A private directory under the
    user's cache is used only when the runtime directory is absent, for
    example in a headless test harness.
    """
    value = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(value) if value else user_cache_dir() / "run"
    return base / APP_SLUG


def catalogue_dir() -> Path:
    return user_data_dir() / "catalogue"


def certificate_dir() -> Path:
    return user_data_dir() / "certificates" / "nm-openvpn"


def ownership_manifest_path() -> Path:
    return user_data_dir() / "ownership.json"


def settings_path() -> Path:
    return user_data_dir() / "settings.json"


def ensure_private_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(mode)
    except OSError:
        pass
    return path
