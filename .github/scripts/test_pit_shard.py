import tempfile
import unittest
from pathlib import Path

from pit_shard import classes, main, shards, target_classes


def tree(files):
    root = Path(tempfile.mkdtemp())
    for name, size in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x" * size)
    return root


class PitShardTest(unittest.TestCase):
    FILES = {
        "space/seclume/tls/Big.java": 900,
        "space/seclume/tls/Mid.java": 500,
        "space/seclume/tls/Small.java": 300,
        "space/seclume/tls/Tiny.java": 100,
        "space/seclume/tls/sub/Deep.java": 450,
        "space/seclume/tls/package-info.java": 5000,
        "space/seclume/other/Elsewhere.java": 9000,
    }

    def test_every_class_of_the_package_and_its_subpackages_is_in_exactly_one_shard(self):
        root = tree(self.FILES)
        for count in (1, 2, 3, 4, 5):
            found = [name for shard in shards(root, "space.seclume.tls", count) for name in shard]
            self.assertEqual(sorted(found), sorted(set(found)), f"{count} shards")
            self.assertEqual(["space.seclume.tls.Big", "space.seclume.tls.Mid", "space.seclume.tls.Small",
                              "space.seclume.tls.Tiny", "space.seclume.tls.sub.Deep"], sorted(found))

    def test_the_largest_files_are_spread_first(self):
        root = tree(self.FILES)
        # 900, 500, 450, 300, 100 bytes: each to the shard with the fewest bytes so far.
        self.assertEqual([["space.seclume.tls.Big", "space.seclume.tls.Small"],
                          ["space.seclume.tls.Mid", "space.seclume.tls.Tiny", "space.seclume.tls.sub.Deep"]],
                         shards(root, "space.seclume.tls", 2))
        self.assertEqual([["space.seclume.tls.Big"], ["space.seclume.tls.Mid", "space.seclume.tls.Tiny"],
                          ["space.seclume.tls.Small", "space.seclume.tls.sub.Deep"]],
                         shards(root, "space.seclume.tls", 3))

    def test_package_info_is_no_class(self):
        root = tree(self.FILES)
        self.assertNotIn("space.seclume.tls.package-info",
                         [name for _, name in classes(root, "space.seclume.tls")])

    def test_nested_classes_go_with_their_class(self):
        self.assertEqual("space.seclume.tls.Big,space.seclume.tls.Big$*", target_classes(["space.seclume.tls.Big"]))

    def test_a_shard_outside_the_count_or_without_a_class_is_refused(self):
        root = tree(self.FILES)
        with self.assertRaises(ValueError):
            main(str(root), "space.seclume.tls", "0", "2")
        with self.assertRaises(ValueError):
            main(str(root), "space.seclume.tls", "6", "6")


if __name__ == "__main__":
    unittest.main()
