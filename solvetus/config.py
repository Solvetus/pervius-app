"""Static configuration for Solvetus VPN Manager.

No secret material belongs in this file or in any file derived from it.
"""

from __future__ import annotations

import os
import pwd
import uuid
from pathlib import Path

APP_ID = "org.solvetus.VPNManager"
APP_NAME = "Solvetus VPN Manager"
APP_SLUG = "solvetus-vpn"
VERSION = "0.1.19"

# Public catalogue snapshot.  The app validates the archive and every profile
# before it will import anything.  Refresh cadence is not guaranteed by the
# upstream provider.
CATALOGUE_URL = "https://vpn.ncapi.io/groupedServerList.zip"
PUBLIC_IP_URL = "https://api64.ipify.org?format=json"
USER_AGENT = f"SolvetusVPNManager/{VERSION} (NetworkManager OpenVPN front end)"

# Resource limits, deliberately conservative.
MAX_ARCHIVE_BYTES = 5 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 1000
MAX_PROFILE_BYTES = 512 * 1024
MAX_CA_BYTES = 256 * 1024
MAX_REMOTES = 64

# One reusable, app-owned NetworkManager profile in v1.
MANAGED_CONNECTION_ID = "Solvetus VPN (managed)"
MANAGED_UUID = str(uuid.uuid5(uuid.NAMESPACE_DNS, "org.solvetus.vpn.managed-profile"))
MANAGED_CONNECTION_TYPE = "vpn"
OPENVPN_SERVICE_TYPE = "org.freedesktop.NetworkManager.openvpn"

# Tray status icons: red when down, green with a check when the tunnel is up.
TRAY_ICON_CONNECTED = f"{APP_ID}-connected"
TRAY_ICON_DISCONNECTED = f"{APP_ID}-disconnected"


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
SECRET_SCHEMA_NAME = "org.solvetus.vpn"
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
