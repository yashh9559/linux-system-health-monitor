import argparse
import tempfile
import unittest
from pathlib import Path

import health_monitor


class HealthMonitorTests(unittest.TestCase):
    def test_positive_percent_accepts_boundary_values(self):
        self.assertEqual(health_monitor.positive_percent("0"), 0.0)
        self.assertEqual(health_monitor.positive_percent("100"), 100.0)

    def test_positive_percent_rejects_out_of_range_values(self):
        for value in ("-1", "100.1", "abc"):
            with self.subTest(value=value):
                with self.assertRaises(Exception):
                    health_monitor.positive_percent(value)

    def test_append_log_writes_one_json_line(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "subdir" / "monitor.jsonl"
            sample = {"timestamp": "2026-01-01T00:00:00+00:00", "warnings": []}
            health_monitor.append_log(log_path, sample)
            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0]), sample)

    def test_disk_usage_reports_requested_path(self):
        result = health_monitor.disk_usage("/")
        self.assertEqual(result["path"], "/")
        self.assertIn("available", result)
        if result["available"]:
            self.assertGreater(result["total_gb"], 0)


if __name__ == "__main__":
    unittest.main()
