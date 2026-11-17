import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from routing.domain_shards import SHARD_KEYS, _rules, shard_key, write_domain_shards


class ShardKeyTests(unittest.TestCase):
    def test_ascii_letter_and_digit(self):
        self.assertEqual(shard_key("youtube.com"), "y")
        self.assertEqual(shard_key("4pda.to"), "4")

    def test_uppercase_is_lowered(self):
        self.assertEqual(shard_key("Rutracker.org"), "r")

    def test_non_ascii_and_empty_fall_back(self):
        self.assertEqual(shard_key("пример.рф"), "_")
        self.assertEqual(shard_key(""), "_")
        self.assertEqual(shard_key(".example.com"), "_")


class RulesTests(unittest.TestCase):
    def test_collects_deduplicates_and_sorts(self):
        payload = {
            "rules": [
                {"domain": ["b.com", "a.com"], "domain_suffix": ["x.com"]},
                {"domain": ["a.com"], "domain_suffix": ["x.com", "y.com"]},
                {"domain": "not-a-list"},
                "not-a-dict",
            ]
        }
        self.assertEqual(_rules(payload), {"domain": ["a.com", "b.com"], "domain_suffix": ["x.com", "y.com"]})

    def test_missing_rules(self):
        self.assertEqual(_rules({}), {"domain": [], "domain_suffix": []})


class WriteShardsTests(unittest.TestCase):
    def _write(self, payload):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source = tmp / "blocked-domains.json"
        source.write_text(json.dumps(payload), encoding="utf-8")
        destination = tmp / "domains"
        return destination, write_domain_shards(source, destination)

    def test_suffix_rule_lands_in_its_own_shard(self):
        destination, _ = self._write({"version": 3, "rules": [{"domain_suffix": ["rutracker.org"]}]})
        shard = json.loads((destination / "r.json").read_text(encoding="utf-8"))
        self.assertEqual(shard["rules"], [{"domain": [], "domain_suffix": ["rutracker.org"]}])

    def test_index_counts_and_files(self):
        destination, index = self._write(
            {
                "version": 3,
                "rules": [{"domain": ["a.com"], "domain_suffix": ["b.com", "4pda.to", "сайт.рф"]}],
            }
        )
        self.assertEqual(
            sorted(p.name for p in destination.iterdir()),
            ["4.json", "_.json", "a.json", "b.json", "index.json"],
        )
        self.assertEqual(index["version"], 3)
        self.assertEqual(index["source"], "blocked-domains.json")
        self.assertEqual(sorted(index["shards"]), ["4", "_", "a", "b"])
        self.assertEqual(index["total"], {"domain": 1, "domain_suffix": 3})
        self.assertEqual(index["shards"]["b"], {"domain": 0, "domain_suffix": 1})

    def test_written_keys_are_known(self):
        destination, _ = self._write({"version": 1, "rules": [{"domain_suffix": ["example.com"]}]})
        for path in destination.glob("*.json"):
            self.assertIn(path.stem, (*SHARD_KEYS, "index"))


if __name__ == "__main__":
    unittest.main()
