"""Non-secret application settings."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import settings_path
from .catalogue.store import atomic_write
from .i18n import SUPPORTED_LANGUAGES
from .killswitchd.rules import MAX_INTERFACES, RulesError, validate_ifname


@dataclass
class Settings:
    username: str = ""
    location_key: str = ""
    protocol: str = "udp"
    save_password: bool = True
    auto_reconnect: bool = True
    notifications_enabled: bool = True
    favorites: list[str] = field(default_factory=list)
    killswitch_allow_lan: bool = False
    last_version: str = ""
    # "" follows the system language; otherwise one of SUPPORTED_LANGUAGES.
    language: str = ""
    # ISP and VPN exit IPs are masked until the user reveals them.
    show_ip_addresses: bool = False
    # IPv6 leak guard while the managed VPN is up.
    block_ipv6: bool = True
    # Interfaces the kill switch and the IPv6 guard always allow (e.g. wt0).
    killswitch_interfaces: list[str] = field(default_factory=list)
    # Last window size (0 = never saved, use the default) and maximised state.
    window_width: int = 0
    window_height: int = 0
    window_maximized: bool = False

    @classmethod
    def from_dict(cls, value: dict) -> "Settings":
        if not isinstance(value, dict):
            return cls()
        protocol = value.get("protocol")
        if protocol not in {"udp", "tcp"}:
            protocol = "udp"
        auto_reconnect = value.get("auto_reconnect", True)
        if not isinstance(auto_reconnect, bool):
            auto_reconnect = True
        notifications_enabled = value.get("notifications_enabled", True)
        if not isinstance(notifications_enabled, bool):
            notifications_enabled = True
        killswitch_allow_lan = value.get("killswitch_allow_lan", False)
        if not isinstance(killswitch_allow_lan, bool):
            killswitch_allow_lan = False
        favorites: list[str] = []
        raw_favorites = value.get("favorites", [])
        if isinstance(raw_favorites, list):
            for item in raw_favorites:
                if not isinstance(item, str):
                    continue
                key = item.strip()
                if (
                    key
                    and len(key) <= 512
                    and "/" in key
                    and key not in favorites
                ):
                    favorites.append(key)
                if len(favorites) >= 50:
                    break
        def flag(name: str, default: bool) -> bool:
            item = value.get(name, default)
            return item if isinstance(item, bool) else default

        interfaces: list[str] = []
        raw_interfaces = value.get("killswitch_interfaces", [])
        if isinstance(raw_interfaces, list):
            for item in raw_interfaces:
                try:
                    name = validate_ifname(item)
                except RulesError:
                    continue
                if name not in interfaces:
                    interfaces.append(name)
                if len(interfaces) >= MAX_INTERFACES:
                    break
        def dimension(name: str) -> int:
            item = value.get(name, 0)
            if isinstance(item, bool) or not isinstance(item, int):
                return 0
            return item if 200 <= item <= 10000 else 0

        window_width, window_height = dimension("window_width"), dimension("window_height")
        if not (window_width and window_height):
            window_width = window_height = 0
        language = value.get("language", "")
        if language not in SUPPORTED_LANGUAGES:
            language = ""
        return cls(
            username=str(value.get("username") or "")[:255],
            location_key=str(value.get("location_key") or "")[:512],
            protocol=protocol,
            save_password=bool(value.get("save_password", True)),
            auto_reconnect=auto_reconnect,
            notifications_enabled=notifications_enabled,
            favorites=favorites,
            killswitch_allow_lan=killswitch_allow_lan,
            last_version=str(value.get("last_version") or "")[:32],
            language=language,
            show_ip_addresses=flag("show_ip_addresses", False),
            block_ipv6=flag("block_ipv6", True),
            killswitch_interfaces=interfaces,
            window_width=window_width,
            window_height=window_height,
            window_maximized=flag("window_maximized", False),
        )


class SettingsStore:
    def __init__(self, path: Path | None = None):
        self.path = path or settings_path()

    def load(self) -> Settings:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return Settings()
        except OSError:
            return Settings()
        try:
            value = json.loads(raw)
        except ValueError:
            return Settings()
        return Settings.from_dict(value)

    def save(self, settings: Settings) -> None:
        data = json.dumps(asdict(settings), indent=2, sort_keys=True) + "\n"
        atomic_write(self.path, data.encode("utf-8"))
