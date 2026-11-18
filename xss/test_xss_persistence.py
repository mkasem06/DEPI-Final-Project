import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import database


class TestFindingPersistence(unittest.TestCase):
    def test_incomplete_xss_findings_are_visible_without_including_failed_scans(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "scans.db"
            connections = []
            connect = database.sqlite3.connect

            def tracked_connect(*args, **kwargs):
                connection = connect(*args, **kwargs)
                connections.append(connection)
                return connection

            try:
                with patch.object(database, "DB_PATH", database_path), patch.object(
                    database.sqlite3, "connect", side_effect=tracked_connect
                ):
                    database.init_db()
                    database.save_scan(
                        "https://example.com",
                        "xss",
                        "incomplete",
                        [{"module": "xss", "finding": "confirmed-xss"}],
                    )
                    database.save_scan(
                        "https://example.com",
                        "xss",
                        "failed",
                        [{"module": "xss", "finding": "failed-xss"}],
                    )
                    database.save_scan(
                        "https://example.com",
                        "sqli",
                        "incomplete",
                        [{"module": "sqli", "finding": "incomplete-sqli"}],
                    )
                    database.save_scan(
                        "https://example.com",
                        "sqli",
                        "completed",
                        [{"module": "sqli", "finding": "completed-sqli"}],
                    )

                    all_findings = database.get_all_findings()
                    xss_findings = database.get_all_findings(module="XSS")
            finally:
                for connection in connections:
                    connection.close()

        self.assertEqual(
            {finding["finding"] for finding in all_findings},
            {"confirmed-xss", "completed-sqli"},
        )
        self.assertEqual(
            [finding["finding"] for finding in xss_findings],
            ["confirmed-xss"],
        )


if __name__ == "__main__":
    unittest.main()
