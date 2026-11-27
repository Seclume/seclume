import unittest

import gate_ratchet

BASE_GATE = {"platforms": ["linux-x64", "linux-arm64"], "groups": {"core": [
    {"test": "a.Wipes", "module": "m", "property": "p", "methods": ["one", "two"],
     "min_cases": 4}]}}
BASE_FLOORS = {"total": {"line": 71, "branch": 65},
               "modules": {"seclume-core": {"line": 80, "branch": 70}}, "packages": {}}


def copy(value):
    import json
    return json.loads(json.dumps(value))


class GateRatchetTest(unittest.TestCase):

    def test_the_same_or_stricter_passes(self):
        gate, floors = copy(BASE_GATE), copy(BASE_FLOORS)
        gate["groups"]["core"][0]["min_cases"] = 5
        gate["groups"]["core"][0]["methods"].append("three")
        floors["total"]["line"] = 72
        self.assertEqual([], gate_ratchet.gate_weakenings(BASE_GATE, gate))
        self.assertEqual([], gate_ratchet.floor_weakenings(BASE_FLOORS, floors))

    def test_every_kind_of_weakening_is_found(self):
        gate = copy(BASE_GATE)
        entry = gate["groups"]["core"][0]
        entry["methods"].remove("two")
        entry["min_cases"] = 1
        entry["skips"] = {"linux-arm64": "no hardware"}
        entry["platforms"] = ["linux-x64"]
        gate["platforms"].remove("linux-arm64")
        found = gate_ratchet.gate_weakenings(BASE_GATE, gate)
        for part in ("method two removed", "min_cases 4 -> 1", "may skip on linux-arm64",
                     "only on linux-x64", "platform linux-arm64 removed"):
            self.assertTrue(any(part in w for w in found), (part, found))
        gate["groups"]["core"] = []
        self.assertIn("gate: core a.Wipes removed", gate_ratchet.gate_weakenings(BASE_GATE, gate))

    def test_a_lowered_or_removed_floor_is_found(self):
        floors = copy(BASE_FLOORS)
        floors["total"]["branch"] = 60
        del floors["modules"]["seclume-core"]
        found = gate_ratchet.floor_weakenings(BASE_FLOORS, floors)
        self.assertIn("floor: total total branch 65 -> 60", found)
        self.assertIn("floor: modules seclume-core line removed", found)

    def test_a_weakening_passes_only_where_the_file_says_why(self):
        gate = copy(BASE_GATE)
        gate["groups"]["core"][0]["min_cases"] = 2
        weaker = gate_ratchet.gate_weakenings(BASE_GATE, gate)
        self.assertEqual(weaker, gate_ratchet.unexplained(weaker, gate))
        gate["relaxed"] = [{"what": weaker[0], "why": ""}]
        self.assertEqual(weaker, gate_ratchet.unexplained(weaker, gate), "an empty reason is none")
        gate["relaxed"] = [{"what": weaker[0], "why": "two cases were duplicates"}]
        self.assertEqual([], gate_ratchet.unexplained(weaker, gate))


if __name__ == "__main__":
    unittest.main()
