from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue_candidate import candidate_from_issue, markdown


class IssueCandidateTests(unittest.TestCase):
    def test_domain_candidate_is_reviewed_and_limited(self):
        issue = {"number": 7, "title": "Unrouted service", "html_url": "https://example.com/issues/7",
                 "body": "### Resource\nexample.com\n\n### Provider\nTest ISP\n\n### Expected\nVPN\n\n### Actual\nDirect"}
        candidate = candidate_from_issue(issue)
        self.assertEqual(candidate["kind"], "domain_suffix")
        self.assertEqual(candidate["domain"], "example.com")
        self.assertIn("Issue #7", candidate["reason"])
        self.assertIn("202", candidate["review_after"])
        self.assertIn("config/manual-vpn.json", markdown(candidate, issue))

    def test_ip_candidate_is_exact(self):
        issue = {"number": 8, "title": "Unrouted IP", "html_url": "https://example.com/issues/8",
                 "body": "### Resource\n1.1.1.1/32"}
        candidate = candidate_from_issue(issue)
        self.assertEqual(candidate, {**candidate, "kind": "ip_cidr", "domain": "1.1.1.1/32"})
        with self.assertRaises(ValueError):
            candidate_from_issue({"number": 9, "title": "bad", "html_url": "https://example.com/9",
                                  "body": "### Resource\n10.0.0.0/8"})


if __name__ == "__main__":
    unittest.main()
