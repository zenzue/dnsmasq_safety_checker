import unittest

from dnsmasq_safety_checker.rules import (
    assess_pihole_ftl,
    assess_upstream_dnsmasq,
    parse_dnsmasq_upstream_version,
)


class RuleTests(unittest.TestCase):
    def test_parse_dnsmasq_version(self):
        self.assertEqual(parse_dnsmasq_upstream_version("Dnsmasq version 2.90"), "2.90")
        self.assertEqual(parse_dnsmasq_upstream_version("dnsmasq-2.92rel2"), "2.92rel2")

    def test_old_upstream_is_review_or_high(self):
        a = assess_upstream_dnsmasq("2.90", exposed=True)
        self.assertEqual(a.severity, "HIGH")
        self.assertIn("LIKELY_VULNERABLE", a.status)

    def test_292_without_rel_is_ambiguous(self):
        a = assess_upstream_dnsmasq("2.92", exposed=True)
        self.assertEqual(a.status, "AMBIGUOUS_2_92_BUILD")

    def test_292rel2_is_fixed(self):
        a = assess_upstream_dnsmasq("2.92rel2", exposed=True)
        self.assertEqual(a.severity, "LOW")

    def test_pihole_fixed(self):
        self.assertEqual(assess_pihole_ftl("6.6.2").severity, "LOW")
        self.assertEqual(assess_pihole_ftl("6.6.1").severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
