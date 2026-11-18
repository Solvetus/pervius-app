"""The language override is applied before GTK and gettext start."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pervius import i18n
from pervius.settings import Settings

PO = '''msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\\n"
"Plural-Forms: nplurals=2; plural=(n > 1);\\n"

msgid "Not connected"
msgstr "Non connecté"
'''


@unittest.skipUnless(shutil.which("msgfmt"), "msgfmt is required")
class LanguageOverrideTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        target = self.tmp / "fr" / "LC_MESSAGES"
        target.mkdir(parents=True)
        (self.tmp / "fr.po").write_text(PO, encoding="utf-8")
        subprocess.run(
            ["msgfmt", "-o", str(target / "pervius.mo"), str(self.tmp / "fr.po")], check=True
        )
        self.env = mock.patch.dict(
            os.environ, {"PERVIUS_LOCALEDIR": str(self.tmp), "LANG": "C.UTF-8"}, clear=False
        )
        self.env.start()
        os.environ.pop("LANGUAGE", None)

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.tmp)
        i18n.setup("")

    def test_override_sets_language_and_translates(self):
        self.assertEqual(i18n.setup("fr"), "fr")
        self.assertEqual(os.environ["LANGUAGE"], "fr_FR:fr")
        self.assertEqual(i18n._("Not connected"), "Non connecté")
        self.assertEqual(i18n.active_language(), "fr")

    def test_system_default_leaves_the_environment_alone(self):
        self.assertEqual(i18n.setup(""), "")
        self.assertNotIn("LANGUAGE", os.environ)
        self.assertEqual(i18n._("Not connected"), "Not connected")

    def test_system_language_is_followed(self):
        os.environ["LANGUAGE"] = "fr"
        i18n.setup("")
        self.assertEqual(i18n._("Not connected"), "Non connecté")

    def test_english_override_beats_the_system_language(self):
        os.environ["LANGUAGE"] = "fr"
        i18n.setup("en")
        self.assertEqual(os.environ["LANGUAGE"], "en")
        self.assertEqual(i18n._("Not connected"), "Not connected")

    def test_unknown_value_follows_the_system(self):
        self.assertEqual(i18n.setup("xx"), "")
        self.assertNotIn("LANGUAGE", os.environ)

    def test_app_main_applies_the_setting_before_gtk_init(self):
        from pervius.ui import app

        order = []
        settings = Settings(language="fr")
        with mock.patch.object(app, "migrate_user_data", lambda: order.append("migrate")), \
                mock.patch.object(app.SettingsStore, "load", lambda self: settings), \
                mock.patch.object(app.i18n, "setup", lambda lang: order.append(f"setup:{lang}")), \
                mock.patch.object(app.Gtk, "init", lambda: order.append("gtk")), \
                mock.patch.object(app.Adw, "init", lambda: order.append("adw")), \
                mock.patch.object(app, "PerviusApplication") as application, \
                mock.patch.object(app.os, "geteuid", lambda: 1000):
            application.return_value.run.return_value = 0
            app.main(["pervius"])
        self.assertEqual(order[:4], ["migrate", "setup:fr", "gtk", "adw"])


class CountryNameTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        i18n.setup("")

    def test_falls_back_to_english_without_translation(self):
        i18n.setup("en")
        self.assertEqual(i18n.country_name("PT", "Portugal"), "Portugal")
        self.assertEqual(i18n.country_name("ZZ", "Nowhere"), "Nowhere")

    @unittest.skipUnless(
        Path("/usr/share/locale/pt/LC_MESSAGES/iso_3166-1.mo").exists(), "iso-codes pt missing"
    )
    def test_iso_codes_translation(self):
        i18n.setup("pt")
        self.assertEqual(i18n.country_name("GB", "United Kingdom"), "Reino Unido")


class SettingsLanguageTests(unittest.TestCase):
    def test_language_is_validated(self):
        self.assertEqual(Settings.from_dict({"language": "pt"}).language, "pt")
        self.assertEqual(Settings.from_dict({"language": "de"}).language, "")
        self.assertEqual(Settings.from_dict({"language": 3}).language, "")
        self.assertEqual(Settings.from_dict({}).language, "")


if __name__ == "__main__":
    unittest.main()
