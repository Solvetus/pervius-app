from __future__ import annotations

import unittest

from pervius.catalogue.countries import (
    COUNTRY_NAMES,
    country_flag,
    country_name,
    fold_text,
)
from pervius.catalogue.models import Location


def location(code: str, city: str) -> Location:
    return Location(country_code=code, city=city, profiles={})


class CountryTests(unittest.TestCase):
    def test_names_and_flags(self):
        self.assertEqual(country_name("PT"), "Portugal")
        self.assertEqual(country_flag("PT"), "\U0001f1f5\U0001f1f9")
        self.assertEqual(country_flag("UK"), "\U0001f1ec\U0001f1e7")
        self.assertEqual(country_name("UK"), "United Kingdom")
        self.assertEqual(country_flag(""), "")
        self.assertEqual(country_flag("X"), "")

    def test_unknown_code_falls_back_to_code(self):
        self.assertEqual(country_name("ZZ"), "ZZ")
        self.assertEqual(country_flag("ZZ"), "\U0001f1ff\U0001f1ff")

    def test_every_country_has_a_two_letter_code_and_name(self):
        self.assertEqual(len(COUNTRY_NAMES), 249)
        for code, name in COUNTRY_NAMES.items():
            self.assertEqual(len(code), 2)
            self.assertTrue(code.isalpha())
            self.assertTrue(name)

    def test_fold_text_removes_accents_and_case(self):
        self.assertEqual(fold_text("Türkiye"), "turkiye")
        self.assertEqual(fold_text("Côte d'Ivoire"), "cote d'ivoire")

    def test_matches_city_country_name_code_and_aliases(self):
        lisbon = location("PT", "Lisbon")
        for query in ("Lisbon", "lisbon", "Portugal", "PT", "portugal lisbon"):
            self.assertTrue(lisbon.matches(query), query)
        self.assertFalse(lisbon.matches("Spain"))

        britain = location("UK", "London")
        for query in ("United Kingdom", "uk", "GB", "Great Britain", "britain"):
            self.assertTrue(britain.matches(query), query)

        america = location("US", "New York")
        for query in ("United States", "usa", "America"):
            self.assertTrue(america.matches(query), query)

    def test_matches_is_accent_insensitive(self):
        city = location("BR", "São Paulo")
        self.assertTrue(city.matches("Sao Paulo"))
        self.assertTrue(city.matches("sao"))

    def test_empty_query_matches_everything(self):
        self.assertTrue(location("DE", "Berlin").matches(""))


if __name__ == "__main__":
    unittest.main()
