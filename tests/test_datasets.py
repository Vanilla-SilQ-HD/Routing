import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from routing.datasets import DATASET_NAMES, DATASETS, dataset_sizes


class DatasetRegistryTests(unittest.TestCase):
    def test_registry_is_unique_and_complete(self):
        self.assertEqual(len(DATASET_NAMES), len(set(DATASET_NAMES)))
        self.assertEqual(DATASET_NAMES, tuple(d.name for d in DATASETS))
        self.assertIn("blocked-domains", DATASET_NAMES)
        self.assertIn("blocked-domains-smart", DATASET_NAMES)
        self.assertIn("routing-direct-exceptions", DATASET_NAMES)
        for dataset in DATASETS:
            self.assertIn(dataset.kind, {"domain", "cidr"})
            self.assertTrue(dataset.title)
            self.assertTrue(dataset.description)

    def test_dataset_sizes_reads_each_manifest_section(self):
        manifest = {
            "output": {"srs_bytes": 100},
            "core": {"output": {"srs_bytes": 40}},
            "smart": {"output": {"srs_bytes": 41}},
            "service_networks": {"output": {"srs_bytes": 50}},
            "registry_ip": {"output": {"srs_bytes": 25}},
            "registry_cidr": {"output": {"srs_bytes": 30}},
            "direct_exceptions": {"output": {"srs_bytes": 17}},
        }
        sizes = dataset_sizes(manifest)
        self.assertEqual(sizes["blocked-domains"], 100)
        self.assertEqual(sizes["blocked-domains-core"], 40)
        self.assertEqual(sizes["blocked-domains-smart"], 41)
        self.assertEqual(sizes["blocked-services-ip"], 50)
        self.assertEqual(set(sizes), set(DATASET_NAMES))


if __name__ == "__main__":
    unittest.main()
