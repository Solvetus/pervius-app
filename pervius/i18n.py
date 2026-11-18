"""Translations (gettext domain ``pervius``).

``setup()`` runs once at startup, before GTK initialises, so both Python
strings and the C libraries (GTK, libadwaita) follow the same language.  The
user's choice in Settings overrides the system language through the
``LANGUAGE`` environment variable; an empty choice follows the system.

Strings are marked with ``_()`` (translate now), ``N_()`` (mark a constant,
translate where it is shown), ``C_(context, text)`` and ``ngettext()``.
Placeholders are positional (``{0}``, ``{1}``) so translators can reorder them.
"""

from __future__ import annotations

import gettext
import json
import locale
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

DOMAIN = "pervius"
SYSTEM_LOCALEDIR = Path("/usr/share/locale")
ISO_CODES_JSON = Path("/usr/share/iso-codes/json/iso_3166-1.json")
ISO_CODES_DOMAIN = "iso_3166-1"

# Settings value -> LANGUAGE environment value.  "" follows the system.
LANGUAGE_ENV = {
    "en": "en",
    "pt": "pt_PT:pt",
    "fr": "fr_FR:fr",
    "es": "es_ES:es",
    "it": "it_IT:it",
}
# Each language is shown in its own name, regardless of the UI language.
LANGUAGE_NAMES = (
    ("en", "English"),
    ("pt", "Português"),
    ("fr", "Français"),
    ("es", "Español"),
    ("it", "Italiano"),
)
SUPPORTED_LANGUAGES = tuple(code for code, _name in LANGUAGE_NAMES)

_translation: gettext.NullTranslations = gettext.NullTranslations()
_countries: gettext.NullTranslations = gettext.NullTranslations()
_iso_names: dict[str, str] | None = None
_active_language = ""


def _(message: str) -> str:
    return _translation.gettext(message)


def N_(message: str) -> str:
    """Mark a string for extraction without translating it yet."""
    return message


def C_(context: str, message: str) -> str:
    return _translation.pgettext(context, message)


def ngettext(singular: str, plural: str, count: int) -> str:
    return _translation.ngettext(singular, plural, count)


def localedir() -> Path:
    """Where the compiled catalogues live.

    ``PERVIUS_LOCALEDIR`` is for development and tests; a source checkout
    uses ``build/i18n/locale`` once ``packaging/build-i18n.sh`` has run;
    installed packages use the system locale directory.
    """
    override = os.environ.get("PERVIUS_LOCALEDIR")
    if override:
        return Path(override)
    source_tree = Path(__file__).resolve().parents[1] / "build" / "i18n" / "locale"
    if source_tree.is_dir():
        return source_tree
    return SYSTEM_LOCALEDIR


def setup(language: str = "", *, environ=None) -> str:
    """Select the UI language.  Returns the language override applied ("" = system).

    Must run before ``Gtk.init()``.  An unknown value follows the system.
    """
    global _translation, _countries, _active_language
    env = os.environ if environ is None else environ
    language = language if language in LANGUAGE_ENV else ""
    if language:
        env["LANGUAGE"] = LANGUAGE_ENV[language]
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error as exc:
        log.info("could not apply the system locale: %s", exc)
    languages = LANGUAGE_ENV[language].split(":") if language else None
    directory = localedir()
    _translation = gettext.translation(
        DOMAIN, str(directory), languages=languages, fallback=True
    )
    _countries = gettext.translation(
        ISO_CODES_DOMAIN, str(SYSTEM_LOCALEDIR), languages=languages, fallback=True
    )
    _active_language = language
    return language


def active_language() -> str:
    return _active_language


def _iso_country_msgids() -> dict[str, str]:
    global _iso_names
    if _iso_names is None:
        names: dict[str, str] = {}
        try:
            entries = json.loads(ISO_CODES_JSON.read_text(encoding="utf-8")).get("3166-1", [])
        except (OSError, ValueError, AttributeError):
            entries = []
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("alpha_2"), str):
                name = entry.get("common_name") or entry.get("name")
                if isinstance(name, str):
                    names[entry["alpha_2"].upper()] = name
        _iso_names = names
    return _iso_names


def country_name(code: str, english: str) -> str:
    """Translate a country name through iso-codes, if it is installed.

    ``english`` is Pervius' own English name; it is kept when iso-codes has no
    translation for the current language.
    """
    msgid = _iso_country_msgids().get((code or "").upper())
    if not msgid:
        return english
    translated = _countries.gettext(msgid)
    return english if translated == msgid else translated
