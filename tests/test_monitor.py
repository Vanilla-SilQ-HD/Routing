from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from monitor import classify_result, html_report


class MonitorTests(unittest.TestCase):
    def test_http_statuses_are_classified_without_changing_routes(self):
        self.assertEqual(classify_result({"statusCode": 200}), "works_direct")
        self.assertEqual(classify_result({"statusCode": 403}), "blocked_or_geo")
        self.assertEqual(classify_result({"statusCode": 500}), "down_or_error")
        self.assertEqual(classify_result({"statusCode": 429}), "unknown")
        self.assertEqual(classify_result({"status": "aborted"}), "unknown")

    def test_report_contains_history_and_no_vpn_claim(self):
        report = html_report({"history": [{"generated_at": "2026-11-10T00:00:00+00:00", "results": [
            {"target": "example.com", "status": "works_direct", "http_status": 200, "error": None}
        ]}]})
        self.assertIn("example.com", report)
        self.assertIn("не выполняется", report)
        self.assertIn("не меняют маршруты", report)


if __name__ == "__main__":
    unittest.main()
