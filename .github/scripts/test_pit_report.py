import tempfile
import unittest
from pathlib import Path

from pit_report import annotations, read, score, survivors_by_class, MAX_ANNOTATIONS, MAX_CHARS


def mutation(status, cls, line, mutator="NegateConditionalsMutator", method="check",
             description="negated conditional"):
    package, name = cls.rsplit(".", 1)
    return (f'<mutation detected="{str(status == "KILLED").lower()}" status="{status}" numberOfTestsRun="1">'
            f"<sourceFile>{name}.java</sourceFile><mutatedClass>{cls}</mutatedClass>"
            f"<mutatedMethod>{method}</mutatedMethod><lineNumber>{line}</lineNumber>"
            f"<mutator>org.pitest.mutationtest.engine.gregor.mutators.{mutator}</mutator>"
            f"<description>{description}</description></mutation>")


def report(*mutations):
    directory = tempfile.mkdtemp()
    path = Path(directory) / "mutations.xml"
    path.write_text("<?xml version='1.0' encoding='UTF-8'?><mutations>" + "".join(mutations) + "</mutations>",
                    encoding="utf-8")
    return path


class PitReportTest(unittest.TestCase):
    def test_the_score_counts_killed_against_what_a_test_ran(self):
        found = read(report(
            mutation("KILLED", "space.seclume.crypto.Hmac", 10),
            mutation("TIMED_OUT", "space.seclume.crypto.Hmac", 11),
            mutation("SURVIVED", "space.seclume.crypto.Hmac", 12),
            mutation("NO_COVERAGE", "space.seclume.crypto.Cng", 5)))
        self.assertEqual((2, 3, 1, 4), score(found))

    def test_survivors_are_grouped_by_class_most_first_and_by_line(self):
        found = read(report(
            mutation("SURVIVED", "space.seclume.secret.A", 30),
            mutation("SURVIVED", "space.seclume.secret.B", 9),
            mutation("SURVIVED", "space.seclume.secret.B", 3, mutator="VoidMethodCallMutator",
                     description="removed call to wipe"),
            mutation("KILLED", "space.seclume.secret.C", 1)))
        grouped = survivors_by_class(found)
        self.assertEqual(["space.seclume.secret.B", "space.seclume.secret.A"], list(grouped))
        self.assertEqual([3, 9], [m["line"] for m in grouped["space.seclume.secret.B"]])
        self.assertEqual("VoidMethodCallMutator", grouped["space.seclume.secret.B"][0]["mutator"])

    def test_an_annotation_names_the_file_line_and_what_was_changed(self):
        found = read(report(mutation("SURVIVED", "space.seclume.field.BlindIndex", 140,
                                     mutator="VoidMethodCallMutator", method="matches",
                                     description="removed call to java/lang/foreign/MemorySegment::fill")))
        [(path, line, title, text)] = annotations(survivors_by_class(found), "seclume-core/src/main/java")
        self.assertEqual("seclume-core/src/main/java/space/seclume/field/BlindIndex.java", path)
        self.assertEqual(140, line)
        self.assertEqual("survivors: BlindIndex", title)
        self.assertIn("140 matches: VoidMethodCallMutator - removed call to", text)

    def test_many_classes_fit_ten_annotations_and_the_rest_are_named(self):
        mutations = []
        for c in range(100):
            for line in range(1, 6):
                mutations.append(mutation("SURVIVED", f"space.seclume.crypto.Class{c:02d}", line,
                                          description="x" * 120))
        packed = annotations(survivors_by_class(read(report(*mutations))), "src")
        self.assertLessEqual(len(packed), MAX_ANNOTATIONS)
        self.assertTrue(all(len(text) <= MAX_CHARS for _, _, _, text in packed))
        self.assertIn("not shown:", packed[-1][3])

    def test_small_classes_share_an_annotation(self):
        found = read(report(*[mutation("SURVIVED", f"space.seclume.audit.C{i}", 1) for i in range(5)]))
        packed = annotations(survivors_by_class(found), "src")
        self.assertEqual(1, len(packed))
        self.assertEqual("survivors: C0, C1, C2 +2", packed[0][2])

    def test_a_report_with_a_dtd_is_refused(self):
        path = report()
        path.write_text('<!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]><mutations>&x;</mutations>')
        with self.assertRaisesRegex(ValueError, "DTD"):
            read(path)


if __name__ == "__main__":
    unittest.main()
