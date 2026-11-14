import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from pit_report import (annotations, main, read, score, survivors_by_class, test_name,
                        MAX_ANNOTATIONS, MAX_CHARS)


def mutation(status, cls, line, mutator="NegateConditionalsMutator", method="check",
             description="negated conditional", tests_run=1, killing_test=None):
    package, name = cls.rsplit(".", 1)
    killing = f"<killingTest>{killing_test}</killingTest>" if killing_test else ""
    return (f'<mutation detected="{str(status == "KILLED").lower()}" status="{status}" '
            f'numberOfTestsRun="{tests_run}">'
            f"<sourceFile>{name}.java</sourceFile><mutatedClass>{cls}</mutatedClass>"
            f"<mutatedMethod>{method}</mutatedMethod><lineNumber>{line}</lineNumber>"
            f"<mutator>org.pitest.mutationtest.engine.gregor.mutators.{mutator}</mutator>"
            f"<description>{description}</description>{killing}</mutation>")


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


    def test_the_shards_of_a_package_are_scored_together(self):
        first = report(mutation("KILLED", "space.seclume.tls.A", 1), mutation("SURVIVED", "space.seclume.tls.A", 2))
        second = report(mutation("KILLED", "space.seclume.tls.B", 3), mutation("KILLED", "space.seclume.tls.B", 4))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, main(f"{first},{second}", "src", "tls", 75.0))
        self.assertIn("3 of 4 mutants with a test killed (75.0%)", output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, main(f"{first},{second}", "src", "tls", 76.0))

    def test_a_missing_shard_fails_the_package(self):
        first = report(mutation("KILLED", "space.seclume.tls.A", 1))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(1, main(f"{first},/nonexistent/mutations.xml", "src", "tls"))
        self.assertIn("no PIT report at /nonexistent/mutations.xml", output.getvalue())

    def test_a_floor_fails_a_score_below_it_and_only_then(self):
        path = report(mutation("KILLED", "space.seclume.tls.A", 1),
                      mutation("KILLED", "space.seclume.tls.A", 2),
                      mutation("KILLED", "space.seclume.tls.A", 3),
                      mutation("SURVIVED", "space.seclume.tls.A", 4),
                      mutation("NO_COVERAGE", "space.seclume.tls.B", 1))
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.assertEqual(0, main(str(path), "src", "tls"))
            self.assertEqual(0, main(str(path), "src", "tls", 75.0))
            self.assertEqual(1, main(str(path), "src", "tls", 75.1))
            self.assertEqual(1, main(str(path) + ".missing", "src", "tls"))
        text = printed.getvalue()
        self.assertIn("3 of 4 mutants with a test killed (75.0%)", text)
        self.assertIn("3 of all 5 killed (60.0%)", text)
        self.assertIn("below the floor of 75.1%", text)
        self.assertIn("::group::every survivor in tls (1)", text)
        self.assertIn("survivor src/space/seclume/tls/A.java:4 ", text)

    def test_the_log_names_each_timeout_with_its_test_and_how_many_tests_a_survivor_ran(self):
        test_id = ("space.seclume.tls.CertificateMessageTest.[engine:junit-jupiter]"
                   "/[class:space.seclume.tls.CertificateMessageTest]/[method:aWellFormedChainOfTwoPasses()]")
        path = report(mutation("TIMED_OUT", "space.seclume.tls.RecordStream", 160, killing_test=test_id),
                      mutation("TIMED_OUT", "space.seclume.tls.A", 2),
                      mutation("SURVIVED", "space.seclume.tls.A", 4, tests_run=7),
                      mutation("KILLED", "space.seclume.tls.A", 5))
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.assertEqual(0, main(str(path), "src", "tls"))
        text = printed.getvalue()
        self.assertIn("survivor src/space/seclume/tls/A.java:4 check NegateConditionalsMutator: "
                      "negated conditional [7 tests ran]", text)
        self.assertIn("::group::every timeout in tls (2)", text)
        self.assertIn("timeout src/space/seclume/tls/A.java:2 check NegateConditionalsMutator: "
                      "negated conditional - in no test named", text)
        self.assertIn("timeout src/space/seclume/tls/RecordStream.java:160 check NegateConditionalsMutator: "
                      "negated conditional - in CertificateMessageTest#aWellFormedChainOfTwoPasses", text)
        self.assertLess(text.index("A.java:2"), text.index("RecordStream.java:160"), "by class, then line")

    def test_a_test_id_without_a_class_is_named_as_it_is(self):
        self.assertEqual("some.Test.method", test_name("some.Test.method"))
        self.assertEqual("T#each", test_name("[class:a.b.T]/[test-template:each(int)]/[test-template-invocation:#1]"))
        self.assertEqual("T", test_name("[engine:junit-jupiter]/[class:a.b.T]"))


if __name__ == "__main__":
    unittest.main()
