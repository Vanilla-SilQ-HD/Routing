import json
import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPILER = ROOT / ".tools" / ("sing-box.exe" if os.name == "nt" else "sing-box")


class ExampleConfigTests(unittest.TestCase):
    def test_examples_are_valid_json_with_expected_structure(self):
        for name in ("singbox-router.json", "singbox-client.json"):
            data = json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))
            self.assertIn("dns", data)
            self.assertIn("route", data)
            tags = {rs["tag"] for rs in data["route"]["rule_set"]}
            self.assertIn("routing-direct-exceptions", tags)
            self.assertIn("routing-services", tags)
            self.assertIn("routing-registry-ip", tags)
            # Direct exceptions must be routed before the VPN rule.
            rules = data["route"]["rules"]
            direct_index = next(i for i, r in enumerate(rules) if "routing-direct-exceptions" in r.get("rule_set", []))
            vpn_index = next(i for i, r in enumerate(rules) if r.get("outbound") == "vpn")
            self.assertLess(direct_index, vpn_index)
            self.assertEqual(data["route"]["final"], "direct")
            self.assertEqual(data["route"]["default_domain_resolver"], "dns-direct")
            # DNS: the domain set resolves via VPN, exceptions via the local resolver.
            dns_rules = data["dns"]["rules"]
            self.assertTrue(any(r.get("server") == "dns-vpn" for r in dns_rules))
            self.assertTrue(any(r.get("server") == "dns-direct" for r in dns_rules))

    @unittest.skipUnless(COMPILER.is_file(), "pinned sing-box compiler is not installed")
    def test_examples_pass_sing_box_check(self):
        for name in ("singbox-router.json", "singbox-client.json"):
            result = subprocess.run([str(COMPILER), "check", "--config", str(ROOT / "examples" / name)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{name}: {result.stdout}{result.stderr}")


if __name__ == "__main__":
    unittest.main()
