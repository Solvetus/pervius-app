"""Catalogue package."""

from .models import Catalogue, ImportReport, Location, ParsedProfile, ProfileRef
from .parser import ProfileError, parse_profile
from .store import CatalogueStore, StoreError
from .validator import ArchiveError, CatalogueError, inspect_archive, parse_catalogue, validate_archive

__all__ = [
    "Catalogue",
    "CatalogueError",
    "CatalogueStore",
    "ImportReport",
    "Location",
    "ParsedProfile",
    "ProfileError",
    "ProfileRef",
    "ArchiveError",
    "StoreError",
    "inspect_archive",
    "parse_catalogue",
    "parse_profile",
    "validate_archive",
]
