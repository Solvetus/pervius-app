"""Non-secret application settings."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import settings_path
from .catalogue.store import atomic_write


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
