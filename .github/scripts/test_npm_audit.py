import unittest

from npm_audit import ACCEPTED, findings


def advisory(name, url, severity):
    return {"name": name, "url": url, "severity": severity}


class NpmAuditGateTest(unittest.TestCase):
    def test_accepted_advisory_and_its_dependents_pass(self):
        accepted = next(iter(ACCEPTED))
        report = {"vulnerabilities": {
            "sprintf-js": {"via": [advisory("sprintf-js", accepted, "moderate")]},
            "tedious": {"via": ["sprintf-js"]},
            "azurite": {"via": ["tedious"]},
        }}
        self.assertEqual([], findings(report))

    def test_other_moderate_or_higher_advisories_fail(self):
        report = {"vulnerabilities": {
            "a": {"via": [advisory("a", "https://github.com/advisories/GHSA-aaaa", "moderate")]},
            "b": {"via": [advisory("b", "https://github.com/advisories/GHSA-bbbb", "critical")]},
            "c": {"via": [advisory("c", "https://github.com/advisories/GHSA-cccc", "low")]},
        }}
        self.assertEqual(["a: https://github.com/advisories/GHSA-aaaa",
                          "b: https://github.com/advisories/GHSA-bbbb"], findings(report))

    def test_no_report_entries_pass(self):
        self.assertEqual([], findings({}))


if __name__ == "__main__":
    unittest.main()
