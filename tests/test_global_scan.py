"""Offline tests for global_scan — no network calls are made.

Run:  python -m unittest discover -s tests -v
"""
import unittest

import global_scan


class CountryListTests(unittest.TestCase):
    def test_every_iso_code_is_known(self):
        self.assertEqual(len(global_scan.COUNTRIES), 249)
        self.assertIn("PH", global_scan.COUNTRIES)
        self.assertIn("ID", global_scan.COUNTRIES)

    def test_all_keywords(self):
        self.assertEqual(global_scan.normalize_countries(None), ["all"])
        self.assertEqual(global_scan.normalize_countries(["all"]), ["all"])
        self.assertEqual(global_scan.normalize_countries(["*"]), ["all"])

    def test_parsing_and_dedup(self):
        self.assertEqual(global_scan.normalize_countries(["ph,id"]), ["ID", "PH"])
        self.assertEqual(global_scan.normalize_countries(["PH", "ph", "JP"]), ["JP", "PH"])

    def test_unknown_code_is_rejected(self):
        with self.assertRaises(ValueError):
            global_scan.normalize_countries(["ZZ"])


class PrefixTests(unittest.TestCase):
    def test_sample_address_skips_network_address(self):
        self.assertEqual(global_scan.sample_address("203.0.113.0/24"), "203.0.113.1")
        self.assertEqual(global_scan.sample_address("198.51.100.7/32"), "198.51.100.7")

    def test_sample_address_rejects_garbage(self):
        self.assertIsNone(global_scan.sample_address("not-a-network"))

    def test_fetch_prefixes_from_local_file(self):
        source = "tests/fixtures/prefixes.txt"
        prefixes = global_scan.fetch_prefixes("PH", limit=2, source=source)
        # Largest blocks come first, comments and junk lines are ignored.
        self.assertEqual(prefixes, ["103.0.0.0/8", "49.0.0.0/9"])

    def test_missing_source_returns_empty(self):
        self.assertEqual(global_scan.fetch_prefixes("PH", source="tests/fixtures/nope.txt"), [])


class ProbeTests(unittest.TestCase):
    def test_closed_port_is_reported_not_raised(self):
        # 127.0.0.1 on an unused port: connect must fail fast and be swallowed.
        record = global_scan.probe_host("127.0.0.1", ports=(1,), timeout=0.2)
        self.assertEqual(record["open_ports"], [])
        self.assertEqual(record["ip"], "127.0.0.1")

    def test_scan_countries_with_fixture_has_schema(self):
        report = global_scan.scan_countries(["PH"], samples=1,
                                            source="tests/fixtures/prefixes.txt",
                                            workers=1)
        for key in ("mode", "countries", "ok", "no_data", "reachable_hosts", "duration_seconds"):
            self.assertIn(key, report)
        self.assertEqual(report["countries_requested"], 1)
        self.assertEqual(report["countries"][0]["country"], "PH")


if __name__ == "__main__":
    unittest.main()
