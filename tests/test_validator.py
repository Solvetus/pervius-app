from __future__ import annotations

import io
import unittest
import zipfile
from pathlib import Path

from pervius.catalogue.validator import (
    ArchiveError,
    CatalogueError,
    inspect_archive,
    parse_catalogue,
    validate_archive,
)
from pervius.config import MAX_PROFILE_BYTES

from .fixtures import catalogue_zip, malicious_symlink_zip, profile_text, zip_with


class ValidatorTests(unittest.TestCase):
    def test_valid_catalogue_counts(self):
        catalogue = parse_catalogue(catalogue_zip(), source_url="fixture")
        self.assertEqual(catalogue.profile_count, 6)
        self.assertEqual(len(catalogue.locations), 3)
        self.assertEqual(catalogue.country_count, 3)
        self.assertTrue(all(set(location.protocols) == {"tcp", "udp"} for location in catalogue.locations))

    def test_inspection(self):
        summary = inspect_archive(catalogue_zip())
        self.assertEqual(summary["profile_count"], 6)
        self.assertEqual(summary["protocol_counts"], {"tcp": 3, "udp": 3})
        self.assertEqual(summary["location_count"], 3)

    def test_traversal_rejected(self):
        blob = zip_with({"../evil.ovpn": profile_text().encode()})
        with self.assertRaisesRegex(ArchiveError, "unsafe archive entry path"):
            validate_archive(blob)

    def test_absolute_path_rejected(self):
        blob = zip_with({"/tmp/evil.ovpn": profile_text().encode()})
        with self.assertRaisesRegex(ArchiveError, "absolute archive entry path"):
            validate_archive(blob)

    def test_backslash_rejected(self):
        blob = zip_with({r"tcp\evil.ovpn": profile_text().encode()})
        with self.assertRaisesRegex(ArchiveError, "unsafe archive entry name"):
            validate_archive(blob)

    def test_symlink_rejected(self):
        with self.assertRaisesRegex(ArchiveError, "non-regular archive entry"):
            validate_archive(malicious_symlink_zip())

    def test_duplicate_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("udp/NCVPN-TS-A-UDP.ovpn", profile_text().encode())
            archive.writestr("udp/NCVPN-TS-A-UDP.ovpn", profile_text().encode())
        with self.assertRaisesRegex(ArchiveError, "duplicate archive entry"):
            validate_archive(buffer.getvalue())

    def test_non_profile_rejected(self):
        blob = zip_with({"README.txt": b"hello"})
        with self.assertRaisesRegex(ArchiveError, "unexpected non-profile entry"):
            validate_archive(blob)

    def test_oversized_entry_rejected(self):
        blob = zip_with({"udp/NCVPN-TS-A-UDP.ovpn": b"x" * (MAX_PROFILE_BYTES + 1)})
        with self.assertRaisesRegex(ArchiveError, "too large"):
            validate_archive(blob)

    def test_bad_directory_layout_is_skipped(self):
        blob = zip_with(
            {
                "other/NCVPN-TS-A-UDP.ovpn": profile_text().encode(),
                "udp/NCVPN-TS-B-UDP.ovpn": profile_text().encode(),
            }
        )
        catalogue = parse_catalogue(blob, source_url="fixture")
        self.assertEqual([name for name, _reason in catalogue.skipped], ["other/NCVPN-TS-A-UDP.ovpn"])
        self.assertIn("unexpected directory layout", catalogue.skipped[0][1])

    def test_protocol_mismatch_is_skipped(self):
        blob = zip_with(
            {
                "tcp/NCVPN-TS-A-UDP.ovpn": profile_text(protocol="tcp").encode(),
                "udp/NCVPN-TS-B-UDP.ovpn": profile_text().encode(),
            }
        )
        catalogue = parse_catalogue(blob, source_url="fixture")
        self.assertEqual(len(catalogue.skipped), 1)
        self.assertIn("protocol directory does not match", catalogue.skipped[0][1])

    def test_one_invalid_profile_does_not_fail_the_catalogue(self):
        good = profile_text().encode()
        bad = profile_text(protocol="tcp").replace(
            "verify-x509-name example name-prefix", "verify-x509-name example bogus-type"
        )
        blob = zip_with(
            {
                "udp/NCVPN-TS-A-UDP.ovpn": good,
                "tcp/NCVPN-PK-Islamabad-TCP.ovpn": bad.encode(),
                "udp/NCVPN-OT-B-UDP.ovpn": (profile_text() + "plugin /tmp/x\n").encode(),
            }
        )
        catalogue = parse_catalogue(blob, source_url="fixture")
        self.assertEqual(catalogue.profile_count, 1)
        self.assertEqual(
            sorted(name for name, _reason in catalogue.skipped),
            ["tcp/NCVPN-PK-Islamabad-TCP.ovpn", "udp/NCVPN-OT-B-UDP.ovpn"],
        )
        self.assertTrue(any(":38" in r or "verify-x509-name" in r for _n, r in catalogue.skipped))

    def test_one_argument_verify_x509_profile_is_accepted(self):
        blob = zip_with(
            {
                "tcp/NCVPN-PK-Islamabad-TCP.ovpn": profile_text(protocol="tcp")
                .replace("verify-x509-name example name-prefix", "verify-x509-name example")
                .encode(),
            }
        )
        catalogue = parse_catalogue(blob, source_url="fixture")
        self.assertEqual((catalogue.profile_count, catalogue.skipped), (1, ()))

    def test_catalogue_with_only_invalid_profiles_is_rejected(self):
        blob = zip_with(
            {"udp/NCVPN-TS-A-UDP.ovpn": (profile_text() + "plugin /tmp/x\n").encode()}
        )
        with self.assertRaisesRegex(CatalogueError, "no locations"):
            parse_catalogue(blob, source_url="fixture")

    def test_real_catalogue_snapshot(self):
        path = Path("/tmp/opencode/catalogue/groupedServerList.zip")
        if not path.exists():
            self.skipTest("real catalogue snapshot not available")
        catalogue = parse_catalogue(path.read_bytes(), source_url="snapshot")
        self.assertEqual(catalogue.profile_count, 302)
        self.assertEqual(len(catalogue.locations), 151)
        self.assertEqual(catalogue.country_count, 112)
        self.assertEqual(catalogue.source_sha256, "b086e8e53bcb4b76be08c065e7b6b24e2539dd1df0c66b288e51e75f28ae385f")


if __name__ == "__main__":
    unittest.main()
