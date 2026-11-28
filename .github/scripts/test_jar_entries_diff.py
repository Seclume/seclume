import os
import tempfile
import unittest
import zipfile

from jar_entries_diff import compare


def jar(directory, name, entries, when=(2026, 11, 28, 0, 0, 0)):
    path = os.path.join(directory, name)
    with zipfile.ZipFile(path, "w") as out:
        for entry, data in entries:
            out.writestr(zipfile.ZipInfo(entry, when), data)
    return path


class JarEntriesDiffTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def lines(self, a, b):
        said = []
        compare(a, b, said.append)
        return said

    def test_the_same_jar_says_nothing(self):
        a = jar(self.dir.name, "a.jar", [("A.class", b"\xca\xfe"), ("x.txt", b"1\n")])
        b = jar(self.dir.name, "b.jar", [("A.class", b"\xca\xfe"), ("x.txt", b"1\n")])
        self.assertEqual([], self.lines(a, b))

    def test_an_entry_only_one_has(self):
        a = jar(self.dir.name, "a.jar", [("A.class", b"1"), ("B.class", b"2")])
        b = jar(self.dir.name, "b.jar", [("A.class", b"1"), ("C.class", b"3")])
        said = self.lines(a, b)
        self.assertIn("  only built: B.class", said)
        self.assertIn("  only on Central: C.class", said)

    def test_a_text_entry_shows_its_difference(self):
        a = jar(self.dir.name, "a.jar", [("META-INF/x.json", b"{\n\"a\": 1\n}\n")])
        b = jar(self.dir.name, "b.jar", [("META-INF/x.json", b"{\n\"a\": 2\n}\n")])
        said = self.lines(a, b)
        self.assertTrue(said[0].startswith("  differs: META-INF/x.json"))
        self.assertIn('    -"a": 2', said)
        self.assertIn('    +"a": 1', said)

    def test_line_endings_alone_are_named(self):
        a = jar(self.dir.name, "a.jar", [("A.class", b"\x00one\r\ntwo\xff")])
        b = jar(self.dir.name, "b.jar", [("A.class", b"\x00one\ntwo\xff")])
        self.assertIn("    only line endings", self.lines(a, b))

    def test_a_timestamp_and_the_order(self):
        a = jar(self.dir.name, "a.jar", [("A", b"1"), ("B", b"2")])
        b = jar(self.dir.name, "b.jar", [("B", b"2"), ("A", b"1")], when=(2026, 1, 1, 0, 0, 0))
        said = self.lines(a, b)
        self.assertTrue(any(line.startswith("  timestamp: A") for line in said))
        self.assertIn("  entry order differs from entry 0: A built, B Central", said)

    def test_many_differences_are_cut_short(self):
        a = jar(self.dir.name, "a.jar", [(f"E{i:02}", b"\xff1") for i in range(30)])
        b = jar(self.dir.name, "b.jar", [(f"E{i:02}", b"\xff2") for i in range(30)])
        said = self.lines(a, b)
        self.assertEqual(21, len(said))
        self.assertEqual("  ... 10 more entries differ", said[-1])


if __name__ == "__main__":
    unittest.main()
