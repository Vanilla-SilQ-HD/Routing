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


    def test_load_previous_distinguishes_404_from_real_failures(self):
        import urllib.error

        from monitor import load_previous
        # 404 = first run: empty history is acceptable and considered restored.
        not_found = urllib.error.HTTPError("https://x", 404, "Not Found", {}, None)
        with patch("monitor.request_json", side_effect=not_found):
            result = load_previous("https://example/monitoring.json")
        self.assertEqual(result["history"], [])
        self.assertTrue(result["history_restored"])
        # A server/network error must NOT silently wipe history.
        for exc in (urllib.error.HTTPError("https://x", 500, "Server Error", {}, None),
                    OSError("connection reset"), ValueError("bad json")):
            with patch("monitor.request_json", side_effect=exc):
                result = load_previous("https://example/monitoring.json")
            self.assertEqual(result["history"], [])
            self.assertFalse(result["history_restored"])
        # A successful load is marked restored.
        with patch("monitor.request_json", return_value={"history": [{"generated_at": "t", "results": []}]}):
            result = load_previous("https://example/monitoring.json")
        self.assertTrue(result.get("history_restored", True))
        self.assertEqual(len(result["history"]), 1)


    def test_rotation_is_deterministic_per_seed(self):
        from monitor import select_rotation_targets
        domains = [f"domain{i}.example" for i in range(50)]
        a = select_rotation_targets(domains, 5, "2026-11-13")
        b = select_rotation_targets(domains, 5, "2026-11-13")
        c = select_rotation_targets(domains, 5, "2026-11-14")
        self.assertEqual(a, b)  # same seed -> same sample
        self.assertEqual(len(a), 5)
        self.assertTrue(set(a) <= set(domains))
        self.assertNotEqual(a, c)  # different day -> different sample
        self.assertEqual(select_rotation_targets([], 5, "x"), [])

    def test_stale_candidates_track_consecutive_direct_answers(self):
        from monitor import update_stale_candidates
        previous: dict = {}
        # Run 1: example.com works direct once.
        results = [{"target": "example.com", "status": "works_direct"},
                   {"target": "blocked.example", "status": "blocked_or_geo"}]
        candidates = update_stale_candidates(previous, results, threshold=3)
        self.assertEqual(candidates, [])
        # Runs 2 and 3 keep answering direct; blocked.example never appears as direct.
        update_stale_candidates(previous, results, threshold=3)
        candidates = update_stale_candidates(previous, results, threshold=3)
        self.assertEqual(candidates, [{"domain": "example.com", "consecutive_works_direct": 3}])
        self.assertNotIn("blocked.example", previous["stale_streaks"])
        # A non-direct answer resets the streak.
        reset = [{"target": "example.com", "status": "down_or_error"}]
        candidates = update_stale_candidates(previous, reset, threshold=3)
        self.assertEqual(candidates, [])
        self.assertNotIn("example.com", previous["stale_streaks"])

    def test_load_compact_domains_parses_full_and_domain_lines(self):
        from monitor import load_compact_domains

        class FakeResponse:
            def read(self, _limit):
                return b"full:a.example\ndomain:b.example\n# comment\n\nfull:c.example\n"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class FakeOpener:
            def open(self, request, timeout):
                return FakeResponse()

        with patch("urllib.request.build_opener", return_value=FakeOpener()):
            self.assertEqual(load_compact_domains("https://example/core.txt"),
                             ["a.example", "b.example", "c.example"])
        # Network failure disables rotation without raising.
        with patch("urllib.request.build_opener", side_effect=OSError("down")):
            self.assertEqual(load_compact_domains("https://example/core.txt"), [])


    def test_probe_network_and_asn_are_captured(self):
        results = [{"statusCode": 200, "probe": {"asn": 12345, "network": "ExampleISP"}},
                   {"statusCode": 200, "probe": {"asn": 67890, "network": "OtherNet"}}]
        result = summarize_results("example.com", results)
        self.assertEqual(result["status"], "works_direct")
        self.assertEqual(result["asns"], [12345, 67890])
        self.assertEqual(result["networks"], ["ExampleISP", "OtherNet"])
        self.assertEqual(result["observations"][0]["asn"], 12345)
        self.assertEqual(result["observations"][0]["network"], "ExampleISP")

    def test_globalping_token_is_sent_when_present(self):
        from monitor import request_json

        captured = {}

        class FakeResponse:
            def read(self, _limit):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class FakeOpener:
            def open(self, request, timeout):
                captured["headers"] = dict(request.header_items())
                return FakeResponse()

        with patch("urllib.request.build_opener", return_value=FakeOpener()), \
                patch.dict("os.environ", {"GLOBALPING_TOKEN": "secret-token"}):
            request_json("https://api.example/measurements")
        self.assertEqual(captured["headers"].get("Authorization"), "Bearer secret-token")


if __name__ == "__main__":
    unittest.main()
