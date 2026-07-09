from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from twn_toolkit import create_app
from twn_toolkit.profile_backup import build_reset_stores


class ResetDataTests(unittest.TestCase):
    def test_reset_data_clears_domain_registered_profile_stores(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            paths = []
            for store in build_reset_stores(instance):
                store.replace_all([{"name": "Saved", "value": "present"}])
                paths.append(store.path)
            auth_path = Path(app.instance_path) / "auth.json"
            auth_path.write_text(json.dumps({"users": [{"username": "keep"}]}), encoding="utf-8")

            result = app.test_cli_runner().invoke(args=["reset-data", "--yes"])

            self.assertEqual(result.exit_code, 0)
            self.assertIn("local profile data has been reset", result.output)
            self.assertTrue(auth_path.exists())
            self.assertTrue(paths)
            self.assertTrue(all(not path.exists() for path in paths))


if __name__ == "__main__":
    unittest.main()
