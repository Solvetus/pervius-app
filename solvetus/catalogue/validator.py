"""Catalogue ZIP validation and grouping.

Nothing from the archive is extracted to disk.  Every entry is checked
against conservative size/path/type limits, then parsed by the strict profile
parser before it can appear in the catalogue.
"""

from __future__ import annotations

import hashlib
import io
import re
import stat
import time
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from ..config import (
    MAX_ARCHIVE_BYTES,
    MAX_ARCHIVE_ENTRIES,
    MAX_PROFILE_BYTES,
    MAX_UNCOMPRESSED_BYTES,
)
from .models import Catalogue, Location, ProfileRef, clean_city_name, location_key, utc_now_iso
from .parser import ProfileError, parse_profile

FILENAME_RE = re.compile(r"^NCVPN-([A-Z]{2})-(.+)-(TCP|UDP)\.ovpn$", re.ASCII)


class ArchiveError(ValueError):
    """The catalogue archive is malformed, unsafe, or outside limits."""


class CatalogueError(ValueError):
    """The archive is safe but does not contain a usable catalogue."""


@dataclass(frozen=True)
class ArchiveEntry:
    name: str
    data: bytes


def _safe_name(name: str) -> PurePosixPath:
    if not name or len(name) > 255:
        raise ArchiveError("archive entry has an empty or overlong name")
    if "\x00" in name or "\\" in name:
        raise ArchiveError(f"unsafe archive entry name: {name!r}")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ArchiveError(f"absolute archive entry path: {name!r}")
    path = PurePosixPath(name)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ArchiveError(f"unsafe archive entry path: {name!r}")
    return path


def validate_archive(blob: bytes) -> list[ArchiveEntry]:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("archive data must be bytes")
    blob = bytes(blob)
    if not blob:
        raise ArchiveError("archive is empty")
    if len(blob) > MAX_ARCHIVE_BYTES:
        raise ArchiveError(f"archive exceeds {MAX_ARCHIVE_BYTES} bytes")
    if not zipfile.is_zipfile(io.BytesIO(blob)):
        raise ArchiveError("file is not a ZIP archive")

    entries: list[ArchiveEntry] = []
    seen: set[str] = set()
    total_declared = 0
    total_actual = 0

    try:
        # Some malformed archives only fail when the central directory is read.
        with zipfile.ZipFile(io.BytesIO(blob), "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise ArchiveError("archive has too many entries")

            for info in infos:
                path = _safe_name(info.filename)
                folded = info.filename.casefold()
                if folded in seen:
                    raise ArchiveError(f"duplicate archive entry: {info.filename!r}")
                seen.add(folded)

                if info.flag_bits & 0x1:
                    raise ArchiveError(f"encrypted archive entry: {info.filename!r}")

                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise ArchiveError(f"non-regular archive entry: {info.filename!r}")

                if info.is_dir() or info.filename.endswith("/"):
                    if info.file_size != 0:
                        raise ArchiveError(f"directory entry has data: {info.filename!r}")
                    continue

                if info.file_size < 0 or info.file_size > MAX_PROFILE_BYTES:
                    raise ArchiveError(f"archive entry is too large: {info.filename!r}")
                total_declared += info.file_size
                if total_declared > MAX_UNCOMPRESSED_BYTES:
                    raise ArchiveError("archive expands beyond the uncompressed size limit")

                if path.suffix.lower() != ".ovpn":
                    raise ArchiveError(f"unexpected non-profile entry: {info.filename!r}")

                with archive.open(info, "r") as handle:
                    data = handle.read(MAX_PROFILE_BYTES + 1)
                if len(data) != info.file_size:
                    raise ArchiveError(f"archive entry length mismatch: {info.filename!r}")
                if len(data) > MAX_PROFILE_BYTES:
                    raise ArchiveError(f"archive entry is too large: {info.filename!r}")
                total_actual += len(data)
                if total_actual > MAX_UNCOMPRESSED_BYTES:
                    raise ArchiveError("archive expands beyond the uncompressed size limit")
                entries.append(ArchiveEntry(name=info.filename, data=data))
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"invalid ZIP archive: {exc}") from exc
    except (OSError, EOFError, RuntimeError) as exc:
        raise ArchiveError(f"could not read ZIP archive: {exc}") from exc

    if not entries:
        raise ArchiveError("archive contains no OpenVPN profiles")
    return entries


def _split_entry_name(name: str) -> tuple[str, str, str, str]:
    path = PurePosixPath(name)
    base = path.name
    match = FILENAME_RE.match(base)
    if match is None:
        raise CatalogueError(f"unrecognised profile filename: {name!r}")
    country, city_raw, proto_raw = match.groups()
    try:
        city = clean_city_name(city_raw)
    except ValueError as exc:
        raise CatalogueError(f"invalid city in {name!r}: {exc}") from exc
    protocol = proto_raw.lower()

    # The public catalogue groups profiles under tcp/ and udp/.  Reject
    # surprising layouts rather than guessing.
    parents = path.parts[:-1]
    if len(parents) != 1 or parents[0] not in {"tcp", "udp"}:
        raise CatalogueError(f"unexpected directory layout for {name!r}")
    if parents[0] != protocol:
        raise CatalogueError(f"protocol directory does not match filename: {name!r}")
    return country, city, protocol, base


def parse_catalogue(
    blob: bytes,
    *,
    source_url: str,
    fetched_at: str | None = None,
) -> Catalogue:
    entries = validate_archive(blob)
    by_location: dict[tuple[str, str], dict[str, ProfileRef]] = {}

    for entry in entries:
        country, city, protocol, base = _split_entry_name(entry.name)
        try:
            parsed = parse_profile(entry.data, entry.name)
        except ProfileError as exc:
            raise CatalogueError(str(exc)) from exc
        if parsed.protocol != protocol:
            raise CatalogueError(f"profile protocol does not match filename: {entry.name!r}")
        key = (country, city)
        if protocol in by_location.setdefault(key, {}):
            raise CatalogueError(f"duplicate profile for {country}/{city}/{protocol}")
        by_location[key][protocol] = ProfileRef(
            archive_name=entry.name,
            country_code=country,
            city=city,
            protocol=protocol,
            profile=parsed,
        )

    locations: list[Location] = []
    for (country, city), profiles in by_location.items():
        if not profiles:
            continue
        locations.append(Location(country_code=country, city=city, profiles=dict(profiles)))
    locations.sort(key=lambda item: (item.country_code, item.city.casefold(), item.city))

    if not locations:
        raise CatalogueError("catalogue contains no locations")

    countries = {location.country_code for location in locations}
    return Catalogue(
        source_url=source_url,
        source_sha256=hashlib.sha256(blob).hexdigest(),
        fetched_at=fetched_at or utc_now_iso(),
        locations=tuple(locations),
        profile_count=sum(len(location.profiles) for location in locations),
        country_count=len(countries),
    )


def inspect_archive(blob: bytes) -> dict:
    """Return reproducible, non-secret summary information about an archive."""
    entries = validate_archive(blob)
    catalogue = parse_catalogue(blob, source_url="<local>")
    protocols = {"tcp": 0, "udp": 0}
    for entry in entries:
        try:
            protocol = entry.name.rsplit("-", 1)[1].split(".", 1)[0].lower()
        except IndexError:
            continue
        if protocol in protocols:
            protocols[protocol] += 1
    ca_hashes = {
        ref.profile.ca_sha256
        for location in catalogue.locations
        for ref in location.profiles.values()
    }
    return {
        "archive_sha256": hashlib.sha256(blob).hexdigest(),
        "archive_bytes": len(blob),
        "archive_entries": len(entries),
        "profile_count": catalogue.profile_count,
        "location_count": len(catalogue.locations),
        "country_count": catalogue.country_count,
        "protocol_counts": protocols,
        "ca_sha256": sorted(ca_hashes),
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
