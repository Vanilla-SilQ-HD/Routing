import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from routing.formats import adguard_upstream, dnsmasq_nfset, ipset_domains, mihomo_yaml

RULES = {"domain": ["exact.example"], "domain_suffix": ["blocked.example"], "ip_cidr": ["1.1.1.1/32"]}


class FormatTests(unittest.TestCase):
    def test_dnsmasq_nfset(self):
        out = dnsmasq_nfset(RULES, "vpn")
        self.assertIn("nftset=/exact.example/vpn", out)
        self.assertIn("nftset=/*.blocked.example/vpn", out)
        self.assertNotIn("1.1.1.1", out)

    def test_ipset_domains(self):
        out = ipset_domains(RULES)
        self.assertEqual(out.splitlines(), ["exact.example", "blocked.example"])

    def test_adguard_upstream(self):
        out = adguard_upstream(RULES, "https://dns.example/dns-query")
        self.assertIn("[/exact.example/]https://dns.example/dns-query", out)
        self.assertIn("[/.blocked.example/]https://dns.example/dns-query", out)

    def test_mihomo_domain_and_ipcidr(self):
        domain = mihomo_yaml(RULES, "domain")
        self.assertIn("behavior=domain", domain)
        self.assertIn("  - 'exact.example'", domain)
        self.assertIn("  - '+.blocked.example'", domain)
        ipcidr = mihomo_yaml(RULES, "ipcidr")
        self.assertIn("behavior=ipcidr", ipcidr)
        self.assertIn("  - '1.1.1.1/32'", ipcidr)
        self.assertNotIn("exact.example", ipcidr)
        with self.assertRaises(ValueError):
            mihomo_yaml(RULES, "bogus")


class ExportScriptTests(unittest.TestCase):
    def _write_set(self, directory, stem, rules):
        (directory / (stem + ".json")).write_text(__import__("json").dumps({"version": 3, "rules": [rules]}), encoding="utf-8")

    def test_export_writes_all_views(self):
        import tempfile

        from export_formats import export
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "dist"
            out = Path(temporary) / "formats"
            build.mkdir()
            for stem in ("blocked-domains", "blocked-domains-core", "blocked-domains-smart"):
                self._write_set(build, stem, RULES)
            self._write_set(build, "blocked-registry-ip", {"ip_cidr": ["1.1.1.1/32"]})
            written = export(build, out, "https://dns.example/dns-query")
            self.assertTrue((out / "dnsmasq-full.conf").is_file())
            self.assertTrue((out / "ipset-smart.txt").is_file())
            self.assertTrue((out / "adguard-compact.txt").is_file())
            self.assertTrue((out / "mihomo-full-domain.yaml").is_file())
            self.assertTrue((out / "mihomo-blocked-registry-ip-ipcidr.yaml").is_file())
            self.assertGreaterEqual(len(written), 10)
            content = (out / "adguard-full.txt").read_text(encoding="utf-8")
            self.assertIn("https://dns.example/dns-query", content)

    def test_export_skips_missing_sets(self):
        import tempfile

        from export_formats import export
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "dist"
            out = Path(temporary) / "formats"
            build.mkdir()
            self._write_set(build, "blocked-domains", RULES)
            written = export(build, out, "https://dns.example/dns-query")
            self.assertTrue((out / "dnsmasq-full.conf").is_file())
            self.assertFalse((out / "dnsmasq-compact.conf").exists())
            self.assertEqual(len(written), 4)

    def test_main_entrypoint(self):
        import tempfile

        from export_formats import main
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "dist"
            out = Path(temporary) / "formats"
            build.mkdir()
            self._write_set(build, "blocked-domains", RULES)
            with patch.object(sys, "argv", ["export_formats.py", "--build-dir", str(build), "--output", str(out)]):
                main()
            self.assertTrue((out / "dnsmasq-full.conf").is_file())


if __name__ == "__main__":
    unittest.main()
