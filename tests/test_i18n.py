"""Translation catalogues: complete, current, and compiled at build time only."""

from __future__ import annotations

import configparser
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PO = REPO / "po"
LANGUAGES = tuple((PO / "LINGUAS").read_text().split())
TOOLS = all(shutil.which(tool) for tool in ("msgfmt", "xgettext", "msgmerge"))
PLACEHOLDER = re.compile(r"\{\d+\}")
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"


def unquote(block: str) -> str:
    return "".join(
        bytes(part, "utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8")
        for part in re.findall(r'"((?:[^"\\]|\\.)*)"', block)
    )


def entries(path: Path) -> dict[tuple[str, str], dict]:
    """Parse a .po/.pot file into {(context, msgid): {"plural", "strs"}}."""
    text = path.read_text(encoding="utf-8")
    result = {}
    for chunk in re.split(r"\n\s*\n", text):
        lines = [line for line in chunk.splitlines() if not line.startswith("#")]
        if not lines:
            continue
        fields: dict[str, list[str]] = {}
        key = None
        for line in lines:
            match = re.match(r'(msgctxt|msgid_plural|msgid|msgstr(?:\[\d\])?) (".*")$', line)
            if match:
                key = match.group(1)
                fields[key] = [match.group(2)]
            elif line.startswith('"') and key:
                fields[key].append(line)
        if "msgid" not in fields:
            continue
        msgid = unquote("\n".join(fields["msgid"]))
        context = unquote("\n".join(fields.get("msgctxt", [])))
        strs = [unquote("\n".join(v)) for k, v in sorted(fields.items()) if k.startswith("msgstr")]
        plural = unquote("\n".join(fields["msgid_plural"])) if "msgid_plural" in fields else None
        result[(context, msgid)] = {"plural": plural, "strs": strs}
    return result


@unittest.skipUnless(TOOLS, "GNU gettext tools are required")
class CatalogueTests(unittest.TestCase):
    def test_languages(self):
        self.assertEqual(LANGUAGES, ("pt", "fr", "es", "it"))
        for lang in LANGUAGES:
            self.assertTrue((PO / f"{lang}.po").is_file(), lang)

    def test_every_catalogue_is_complete_and_valid(self):
        for lang in LANGUAGES:
            result = subprocess.run(
                ["msgfmt", "--check", "--statistics", "-o", os.devnull, str(PO / f"{lang}.po")],
                capture_output=True,
                text=True,
                env={**os.environ, "LC_ALL": "C"},
            )
            self.assertEqual(result.returncode, 0, f"{lang}: {result.stderr}")
            stats = result.stderr.strip()
            self.assertRegex(stats, r"^\d+ translated messages?\.$", f"{lang}: {stats}")

    def test_no_fuzzy_or_obsolete_entries(self):
        for lang in LANGUAGES:
            text = (PO / f"{lang}.po").read_text(encoding="utf-8")
            self.assertNotIn("#, fuzzy", text, lang)
            self.assertNotRegex(text, r"(?m)^#~", lang)

    def test_catalogues_match_the_template(self):
        template = set(entries(PO / "pervius.pot")) - {("", "")}
        for lang in LANGUAGES:
            self.assertEqual(set(entries(PO / f"{lang}.po")) - {("", "")}, template, lang)

    def test_template_is_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            pot = Path(tmp) / "pervius.pot"
            subprocess.run(
                ["sh", str(REPO / "scripts" / "update-pot.sh"), "--pot-only"],
                check=True,
                env={**os.environ, "POT": str(pot)},
                capture_output=True,
            )
            fresh = entries(pot)
        committed = entries(PO / "pervius.pot")
        self.assertEqual(set(fresh), set(committed), "run scripts/update-pot.sh")

    def test_placeholders_and_plurals_are_kept(self):
        for lang in LANGUAGES:
            for (_context, msgid), entry in entries(PO / f"{lang}.po").items():
                if not msgid:
                    continue
                wanted = set(PLACEHOLDER.findall(msgid + (entry["plural"] or "")))
                expected_forms = 2 if entry["plural"] is not None else 1
                self.assertEqual(len(entry["strs"]), expected_forms, (lang, msgid))
                for translated in entry["strs"]:
                    self.assertTrue(translated.strip(), (lang, msgid))
                    found = set(PLACEHOLDER.findall(translated))
                    # A singular form may name the count in words, but never adds placeholders.
                    self.assertTrue(found <= wanted, (lang, msgid, translated))
                    if entry["plural"] is None:
                        self.assertEqual(found, wanted, (lang, msgid, translated))

    def test_protected_names_survive_translation(self):
        names = ("Pervius", "FastVPN", "Namecheap, Inc.", "pervius-killswitch disarm", "OpenVPN", "NetworkManager")
        for lang in LANGUAGES:
            for (_context, msgid), entry in entries(PO / f"{lang}.po").items():
                for name in names:
                    if name in msgid:
                        for translated in entry["strs"]:
                            self.assertIn(name, translated, (lang, msgid))

    def test_no_compiled_catalogues_are_committed(self):
        tracked = subprocess.run(
            ["git", "ls-files", "*.mo", "*.gmo"], cwd=REPO, capture_output=True, text=True
        ).stdout.split()
        self.assertEqual(tracked, [])


@unittest.skipUnless(TOOLS, "GNU gettext tools are required")
class GeneratedFilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        subprocess.run(["sh", str(REPO / "packaging" / "build-i18n.sh"), str(cls.tmp)], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_compiled_catalogues(self):
        for lang in LANGUAGES:
            self.assertTrue((self.tmp / "locale" / lang / "LC_MESSAGES" / "pervius.mo").is_file(), lang)

    def test_desktop_file_is_translated_except_the_name(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read(self.tmp / "com.solvetus.Pervius.desktop", encoding="utf-8")
        entry = parser["Desktop Entry"]
        self.assertEqual(entry["Name"], "Pervius")
        for lang in LANGUAGES:
            self.assertNotIn(f"Name[{lang}]", entry)
            for key in ("GenericName", "Comment", "Keywords"):
                self.assertIn(f"{key}[{lang}]", entry, (lang, key))
            self.assertTrue(entry[f"Keywords[{lang}]"].endswith(";"), lang)
        if shutil.which("desktop-file-validate"):
            subprocess.run(["desktop-file-validate", str(self.tmp / "com.solvetus.Pervius.desktop")], check=True)

    def test_appstream_is_translated(self):
        root = ET.parse(self.tmp / "com.solvetus.Pervius.metainfo.xml").getroot()
        for lang in LANGUAGES:
            summaries = [e for e in root.findall("summary") if e.get(XML_LANG) == lang]
            self.assertEqual(len(summaries), 1, lang)
            paragraphs = [e for e in root.iter("p") if e.get(XML_LANG) == lang]
            self.assertTrue(paragraphs, lang)
        self.assertEqual([e.text for e in root.findall("name")], ["Pervius"])
        if shutil.which("appstreamcli"):
            subprocess.run(
                ["appstreamcli", "validate", "--no-net", str(self.tmp / "com.solvetus.Pervius.metainfo.xml")],
                check=True,
                capture_output=True,
            )


if __name__ == "__main__":
    unittest.main()
