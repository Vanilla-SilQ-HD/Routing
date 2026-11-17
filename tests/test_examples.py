import json
import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPILER = ROOT / ".tools" / ("sing-box.exe" if os.name == "nt" else "sing-box")


class ExampleConfigTests(unittest.TestCase):
    def test_examples_are_valid_json_with_expected_structure(self):
        for name, domain_set in (
            ("singbox-router.json", "routing"),
            ("singbox-client.json", "routing-smart"),
        ):
            with self.subTest(name=name):
                data = json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))
                tags = {rs["tag"] for rs in data["route"]["rule_set"]}
                self.assertGreaterEqual(
                    tags,
                    {"routing-direct-exceptions", domain_set, "routing-services", "routing-registry-ip"},
                )
                rules = data["route"]["rules"]
                direct_index = next(i for i, r in enumerate(rules) if r.get("outbound") == "direct")
                vpn_index = next(i for i, r in enumerate(rules) if r.get("outbound") == "vpn")
                self.assertLess(direct_index, vpn_index)
                self.assertEqual(rules[direct_index]["rule_set"], ["routing-direct-exceptions"])
                self.assertEqual(
                    set(rules[vpn_index]["rule_set"]),
                    {domain_set, "routing-services", "routing-registry-ip"},
                )
                self.assertEqual(data["route"]["final"], "direct")
                self.assertEqual(data["route"]["default_domain_resolver"], "dns-direct")
                servers = {server["tag"]: server for server in data["dns"]["servers"]}
                self.assertEqual(servers["dns-direct"]["type"], "local")
                self.assertEqual(servers["dns-vpn"]["detour"], "vpn")
                self.assertEqual(data["dns"]["final"], "dns-direct")
                self.assertEqual(
                    data["dns"]["rules"],
                    [
                        {"rule_set": ["routing-direct-exceptions"], "server": "dns-direct"},
                        {"rule_set": [domain_set], "server": "dns-vpn"},
                    ],
                )
                outbounds = {outbound["tag"]: outbound for outbound in data["outbounds"]}
                self.assertEqual(outbounds["direct"]["type"], "direct")
                self.assertEqual(outbounds["vpn"]["type"], "socks")
                self.assertEqual(outbounds["vpn"]["server"], "127.0.0.1")
                self.assertEqual(outbounds["vpn"]["server_port"], 1080)

    @unittest.skipUnless(COMPILER.is_file(), "pinned sing-box compiler is not installed")
    def test_examples_pass_sing_box_check(self):
        for name in ("singbox-router.json", "singbox-client.json"):
            result = subprocess.run([str(COMPILER), "check", "--config", str(ROOT / "examples" / name)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{name}: {result.stdout}{result.stderr}")


if __name__ == "__main__":
    unittest.main()
