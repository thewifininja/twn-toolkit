from __future__ import annotations

import re
import unittest

from twn_toolkit.version import APP_VERSION, RELEASE_NOTES


class VersionMetadataTests(unittest.TestCase):
    def test_current_release_note_matches_application_version(self) -> None:
        self.assertTrue(RELEASE_NOTES)
        self.assertEqual(RELEASE_NOTES[0]["version"], APP_VERSION)
        self.assertEqual(APP_VERSION, "0.11.1")
        self.assertIn("Certificate automation beta", RELEASE_NOTES[0]["title"])

    def test_release_versions_are_unique_and_well_formed(self) -> None:
        versions = [release["version"] for release in RELEASE_NOTES]
        self.assertEqual(len(versions), len(set(versions)))
        for version in versions:
            self.assertRegex(version, re.compile(r"^\d+\.\d+\.\d+$"))


if __name__ == "__main__":
    unittest.main()
