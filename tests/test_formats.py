import sys
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
