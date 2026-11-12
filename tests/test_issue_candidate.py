import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue_candidate import candidate_from_issue, markdown


class IssueCandidateTests(unittest.TestCase):
    def test_domain_candidate_is_reviewed_and_limited(self):
        issue = {"number": 7, "title": "Unrouted service", "html_url": "https://example.com/issues/7",
                 "body": "### Resource\nexample.com\n\n### Provider\nTest ISP\n\n### Expected\nVPN\n\n### Actual\nDirect"}
        candidate = candidate_from_issue(issue)
        self.assertEqual(candidate["kind"], "domain")
        self.assertEqual(candidate["domain"], "example.com")
        self.assertIn("Issue #7", candidate["reason"])
        self.assertIn("202", candidate["review_after"])
        self.assertIn("config/manual-vpn.json", markdown(candidate, issue))

    def test_direct_candidate_uses_the_real_russian_form_fields(self):
        issue = {"number": 9, "title": "Unrouted: example.com", "html_url": "https://example.com/issues/9",
                 "body": "### Resource\nexample.com\n\n### Ожидаемый маршрут\nDirect\n\n### Фактический маршрут\nVPN"}
        candidate = candidate_from_issue(issue)
        self.assertEqual(candidate["kind"], "domain")
        self.assertIn("config/direct-exceptions.json", markdown(candidate, issue))
        self.assertNotIn("config/manual-vpn.json", markdown(candidate, issue))
        issue["body"] = issue["body"].replace("### Фактический маршрут\nVPN", "### Фактический маршрут\nDirect")
        with self.assertRaises(ValueError):
            candidate_from_issue(issue)

    def test_ip_candidate_is_exact(self):
        issue = {"number": 8, "title": "Unrouted IP", "html_url": "https://example.com/issues/8",
                 "body": "### Resource\n1.1.1.1/32"}
        candidate = candidate_from_issue(issue)
        self.assertEqual(candidate, {**candidate, "kind": "ip_cidr", "domain": "1.1.1.1/32"})
        with self.assertRaises(ValueError):
            candidate_from_issue({"number": 9, "title": "bad", "html_url": "https://example.com/9",
                                  "body": "### Resource\n10.0.0.0/8"})
    def test_vpn_ip_candidate_requires_manual_review(self):
        issue = {"number": 10, "title": "Unrouted IP", "html_url": "https://example.com/issues/10",
                 "body": "### Resource\n8.8.8.8/32\n\n### Expected\nVPN\n\n### Actual\nDirect"}
        candidate = candidate_from_issue(issue)
        self.assertEqual(candidate["kind"], "ip_cidr")
        self.assertNotIn("config/manual-vpn.json", markdown(candidate, issue))
        self.assertIn("ручной проверки", markdown(candidate, issue))


if __name__ == "__main__":
    unittest.main()
