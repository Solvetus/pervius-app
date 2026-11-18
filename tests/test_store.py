from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path

from solvetus.catalogue.store import CatalogueStore, StoreError, atomic_write
from solvetus.catalogue.validator import parse_catalogue

from .fixtures import catalogue_zip


class StoreTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name) / "catalogue"
        self.blob = catalogue_zip()
        self.catalogue = parse_catalogue(self.blob, source_url="fixture")

    def tearDown(self):
        self._temp.cleanup()

    def test_round_trip(self):
        store = CatalogueStore(self.directory)
        store.save(self.blob, self.catalogue)
        loaded = store.load()
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.profile_count, 6)
        self.assertEqual(loaded.source_sha256, self.catalogue.source_sha256)
        self.assertEqual(loaded.source_url, "fixture")

    def test_files_are_private(self):
        store = CatalogueStore(self.directory)
        store.save(self.blob, self.catalogue)
        self.assertEqual(stat.S_IMODE(store.archive_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(store.index_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_missing_store_returns_none(self):
        store = CatalogueStore(self.directory)
        self.assertIsNone(store.load())

    def test_archive_hash_mismatch_is_rejected(self):
        store = CatalogueStore(self.directory)
        store.save(self.blob, self.catalogue)
        store.archive_path.write_bytes(self.blob[:-10] + b"x" * 10)
        with self.assertRaisesRegex(StoreError, "hash mismatch"):
            store.load()

    def test_mismatched_catalogue_object_is_rejected(self):
        other_blob = catalogue_zip() + b"\x00"
        store = CatalogueStore(self.directory)
        with self.assertRaisesRegex(StoreError, "does not match"):
            store.save(other_blob, self.catalogue)

    def test_corrupt_index_is_rejected(self):
        store = CatalogueStore(self.directory)
        store.save(self.blob, self.catalogue)
        store.index_path.write_text("{not json", encoding="utf-8")
        with self.assertRaisesRegex(StoreError, "could not read cached catalogue"):
            store.load()

    def test_tampered_archive_is_rejected(self):
        store = CatalogueStore(self.directory)
        store.save(self.blob, self.catalogue)
        # Keep the index hash, replace the archive with a different valid ZIP.
        replacement = catalogue_zip()
        replacement = replacement.replace(b"Test City", b"Evil City")
        store.archive_path.write_bytes(replacement)
        expected = hashlib.sha256(self.blob).hexdigest()
        self.assertNotEqual(hashlib.sha256(replacement).hexdigest(), expected)
        with self.assertRaisesRegex(StoreError, "hash mismatch"):
            store.load()

    def test_clear(self):
        store = CatalogueStore(self.directory)
        store.save(self.blob, self.catalogue)
        store.clear()
        self.assertIsNone(store.load())

    def test_atomic_write_replaces_content(self):
        path = Path(self._temp.name) / "nested" / "value.bin"
        atomic_write(path, b"first")
        atomic_write(path, b"second")
        self.assertEqual(path.read_bytes(), b"second")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_index_metadata(self):
        store = CatalogueStore(self.directory)
        store.save(self.blob, self.catalogue)
        metadata = json.loads(store.index_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["format"], 1)
        self.assertEqual(metadata["profile_count"], 6)
        self.assertEqual(metadata["source_sha256"], self.catalogue.source_sha256)


if __name__ == "__main__":
    unittest.main()
