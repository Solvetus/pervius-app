"""Immutable data models for catalogue entries and parsed profiles."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping

from .. import i18n
from .countries import country_flag, country_name, country_search_text, fold_text


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class ParsedProfile:
    """A strictly validated OpenVPN profile."""

    archive_name: str
    protocol: str
    remotes: tuple[tuple[str, int], ...]
    ca_pem: str
    ca_sha256: str
    verify_x509_name: str  # normalized as "type:value"
    auth: str
    data_ciphers: str
    data_ciphers_fallback: str
    tls_cipher: str
    source_sha256: str
    size: int
    low_risk_directives: tuple[str, ...] = ()
    raw: bytes = field(default=b"", repr=False)

    @property
    def remotes_text(self) -> str:
        return ",".join(f"{host}:{port}" for host, port in self.remotes)

    @property
    def verify_x509_type(self) -> str:
        return self.verify_x509_name.split(":", 1)[0]

    @property
    def verify_x509_value(self) -> str:
        return self.verify_x509_name.split(":", 1)[1]


@dataclass(frozen=True)
class ProfileRef:
    archive_name: str
    country_code: str
    city: str
    protocol: str
    profile: ParsedProfile

    @property
    def location_key(self) -> str:
        return location_key(self.country_code, self.city)


@dataclass(frozen=True)
class Location:
    country_code: str
    city: str
    profiles: Mapping[str, ProfileRef]

    @property
    def key(self) -> str:
        return location_key(self.country_code, self.city)

    @property
    def display_city(self) -> str:
        return self.city

    @property
    def display_country(self) -> str:
        """Country name in the UI language (iso-codes), else English."""
        return i18n.country_name(self.country_code, country_name(self.country_code))

    @property
    def country_name(self) -> str:
        return country_name(self.country_code)

    @property
    def flag(self) -> str:
        return country_flag(self.country_code)

    def matches(self, query: str) -> bool:
        """Match city, country code, full country name, and common aliases."""
        terms = fold_text(query).split()
        if not terms:
            return True
        haystack = fold_text(
            " ".join(
                (
                    self.city,
                    self.country_code,
                    country_search_text(self.country_code),
                    self.display_country,
                )
            )
        )
        return all(term in haystack for term in terms)

    @property
    def protocols(self) -> tuple[str, ...]:
        return tuple(sorted(self.profiles))


@dataclass(frozen=True)
class Catalogue:
    source_url: str
    source_sha256: str
    fetched_at: str
    locations: tuple[Location, ...]
    profile_count: int
    country_count: int
    # Archive entries that failed validation and were left out, with reasons.
    skipped: tuple[tuple[str, str], ...] = ()

    def location_by_key(self, key: str) -> Location | None:
        for location in self.locations:
            if location.key == key:
                return location
        return None

    def profile_for(self, location_key_value: str, protocol: str) -> ProfileRef | None:
        location = self.location_by_key(location_key_value)
        if location is None:
            return None
        return location.profiles.get(protocol)


def location_key(country_code: str, city: str) -> str:
    return f"{country_code.upper()}/{city}"


def clean_city_name(raw: str) -> str:
    """Remove the provider's ' - Virtual' server label for display/grouping."""
    city = raw.strip()
    suffix = " - Virtual"
    if city.endswith(suffix):
        city = city[: -len(suffix)].rstrip()
    if not city:
        raise ValueError("empty city name")
    return city


@dataclass
class ImportReport:
    """Non-secret result of an import/verification operation."""

    profile_name: str
    source_sha256: str
    ca_path: str
    ca_sha256: str
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "profile_name": self.profile_name,
            "source_sha256": self.source_sha256,
            "ca_path": self.ca_path,
            "ca_sha256": self.ca_sha256,
            "warnings": list(self.warnings),
        }
