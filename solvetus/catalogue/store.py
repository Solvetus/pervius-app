"""Atomic last-known-good catalogue storage."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from ..config import catalogue_dir, ensure_private_dir
from .models import Catalogue
from .validator import parse_catalogue

INDEX_NAME = "last-known-good.json"
ARCHIVE_NAME = "last-known-good.zip"


class StoreError(RuntimeError):
    pass


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    ensure_private_dir(path.parent)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temp = Path(temp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        try:
            path.chmod(mode)
        except OSError:
            pass
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        finally:
            raise


class CatalogueStore:
    def __init__(self, directory: Path | None = None):
        self.directory = directory or catalogue_dir()
        self.archive_path = self.directory / ARCHIVE_NAME
        self.index_path = self.directory / INDEX_NAME

    def save(self, blob: bytes, catalogue: Catalogue) -> None:
        metadata = {
            "format": 1,
            "source_url": catalogue.source_url,
            "source_sha256": catalogue.source_sha256,
            "fetched_at": catalogue.fetched_at,
            "profile_count": catalogue.profile_count,
            "location_count": len(catalogue.locations),
            "country_count": catalogue.country_count,
        }
        if hashlib.sha256(blob).hexdigest() != catalogue.source_sha256:
            raise StoreError("catalogue object does not match archive bytes")
        atomic_write(self.archive_path, blob)
        atomic_write(
            self.index_path,
            (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    def load(self) -> Catalogue | None:
        if not self.archive_path.exists() or not self.index_path.exists():
            return None
        try:
            blob = self.archive_path.read_bytes()
            metadata = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StoreError(f"could not read cached catalogue: {exc}") from exc
        if not isinstance(metadata, dict):
            raise StoreError("cached catalogue metadata is malformed")
        expected = metadata.get("source_sha256")
        actual = hashlib.sha256(blob).hexdigest()
        if not isinstance(expected, str) or expected != actual:
            raise StoreError("cached catalogue hash mismatch")
        try:
            return parse_catalogue(
                blob,
                source_url=str(metadata.get("source_url") or "<cached>"),
                fetched_at=str(metadata.get("fetched_at") or ""),
            )
        except Exception as exc:
            raise StoreError(f"cached catalogue is invalid: {exc}") from exc

    def clear(self) -> None:
        self.archive_path.unlink(missing_ok=True)
        self.index_path.unlink(missing_ok=True)
