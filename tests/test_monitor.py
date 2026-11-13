import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from monitor import classify_result, html_report, run_probe, summarize_results


class MonitorTests(unittest.TestCase):
    def test_http_statuses_are_classified_without_changing_routes(self):
        self.assertEqual(classify_result({"statusCode": 200}), "works_direct")
        self.assertEqual(classify_result({"statusCode": 403}), "blocked_or_geo")
        self.assertEqual(classify_result({"statusCode": 500}), "down_or_error")
        self.assertEqual(classify_result({"statusCode": 429}), "unknown")
        self.assertEqual(classify_result({"status": "aborted"}), "unknown")
        region_redirect = {"statusCode": 302, "result": {
            "headers": {"location": "https://claude.com/app-unavailable-in-region"},
        }}
        self.assertEqual(classify_result(region_redirect), "blocked_or_geo")
        self.assertEqual(classify_result({"result": {"rawOutput":
            "HTTP/1.1 302\nLocation: https://example.com/app-unavailable-in-region"}}), "blocked_or_geo")
        ordinary_redirect = {"statusCode": 301, "result": {"headers": {"location": "https://example.com/"}}}
        self.assertEqual(classify_result(ordinary_redirect), "works_direct")

    def test_report_contains_history_and_no_vpn_claim(self):
        report = html_report({"history": [{"generated_at": "2026-11-10T00:00:00+00:00", "results": [
            {"target": "example.com", "status": "works_direct", "http_status": 200, "error": None}
        ]}]})
        self.assertIn("example.com", report)
        self.assertIn("не выполняется", report)
        self.assertIn("не меняют маршруты", report)

    def test_all_probes_are_used_and_disagreement_is_unknown(self):
        result = summarize_results("example.com", [{"statusCode": 200}, {"statusCode": 403}])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["probe_statuses"], ["works_direct", "blocked_or_geo"])
        self.assertEqual(len(result["observations"]), 2)
        self.assertIn("inconsistent", result["error"])
        consistent = summarize_results("example.com", [{"statusCode": 403}, {"statusCode": 451}])
        self.assertEqual(consistent["status"], "blocked_or_geo")

    def test_api_failure_is_a_probe_result_not_a_job_crash(self):
        with patch("monitor.create_measurement", side_effect=RuntimeError("Globalping HTTP 429")):
            result = run_probe({}, "example.com")
        self.assertEqual(result["status"], "unknown")
        self.assertIn("429", result["error"])

    def test_external_report_values_are_escaped(self):
        report = html_report({"history": [{"generated_at": "<b>time</b>", "results": [
            {"target": "<script>alert(1)</script>", "status": "unknown", "http_status": None,
             "error": "<img src=x onerror=alert(1)>", "probe_statuses": ["unknown"]}
        ]}]})
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertNotIn("<img src=x onerror=alert(1)>", report)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", report)
        self.assertIn("&lt;b&gt;time&lt;/b&gt;", report)
    def test_insecure_monitoring_url_is_rejected(self):
        from monitor import request_json
        with self.assertRaises(ValueError):
            request_json("http://api.example/measurements")

    def test_empty_measurement_result_is_unknown(self):
        with patch("monitor.create_measurement", return_value={"id": "m1"}), \
                patch("monitor.wait_for_measurement", return_value={"results": []}):
            result = run_probe({"provider": {}}, "example.com")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["error"], "empty result")

    def test_measurement_timeout_is_an_explicit_error(self):
        from monitor import wait_for_measurement
        config = {"provider": {"url": "https://api.example/measurements", "timeout_seconds": -1}}
        with self.assertRaises(TimeoutError):
            wait_for_measurement(config, "m1")

    def test_measurement_request_payload(self):
        from monitor import create_measurement
        config = {"provider": {"url": "https://api.example/measurements", "probes_per_target": 2, "country": "RU"}}
        with patch("monitor.request_json", return_value={"id": "m1"}) as request:
            create_measurement(config, "example.com")
        payload = request.call_args.kwargs["payload"]
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["type"], "http")
        self.assertEqual(payload["limit"], 2)
        self.assertEqual(payload["locations"], [{"country": "RU"}])

    def test_offline_main_preserves_history_without_new_probes(self):
        import json
        import tempfile

        from monitor import main
        config = {"provider": {"name": "Globalping", "url": "https://api.example", "probes_per_target": 1,
                               "country": "RU", "timeout_seconds": 1}, "targets": ["example.com"]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
            previous = {"history": [{"generated_at": "2026-11-01T00:00:00+00:00", "results": []}]}
            with patch("monitor.load_previous", return_value=previous), \
                    patch("monitor.run_probe", side_effect=AssertionError("offline run must not probe")), \
                    patch.object(sys, "argv", ["monitor.py", "--config", str(root / "config.json"),
                                               "--output", str(root / "out.json"), "--html", str(root / "out.html"),
                                               "--offline"]):
                main()
            data = json.loads((root / "out.json").read_text(encoding="utf-8"))
            self.assertEqual(len(data["history"]), 1)
            self.assertEqual(data["automatic_route_changes"], False)
            self.assertEqual(data["vpn_measurement"], "not_performed")
            self.assertTrue((root / "out.html").is_file())


if __name__ == "__main__":
    unittest.main()
