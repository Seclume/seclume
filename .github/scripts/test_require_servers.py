import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from require_servers import main, skipped_for_want_of


def report(directory, module, cases):
    reports = Path(directory) / module / "target" / "surefire-reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "TEST-x.xml").write_text("<testsuite>" + "".join(cases) + "</testsuite>")


class RequireServersTest(unittest.TestCase):
    def test_a_skip_for_want_of_the_jobs_server_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            report(directory, "seclume-mysql", [
                '<testcase classname="A" name="ran"/>',
                '<testcase classname="A" name="lost"><skipped message="Assumption failed: '
                'no MySQL on 127.0.0.1:3307"/></testcase>',
                '<testcase classname="B" name="fixture"><skipped message="Assumption failed: '
                'no .local-mytls12-password"/></testcase>',
            ])
            found = skipped_for_want_of("mysql", directory, "seclume-mysql")
            self.assertEqual([name for name, _ in found], ["A.lost"])
            self.assertEqual(skipped_for_want_of("oracle", directory, "seclume-mysql"), [])

    def test_a_test_that_needs_a_second_server_is_not_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            report(directory, "seclume-sqlserver", [
                '<testcase classname="space.seclume.sqlserver.jdbc.LocalTds8Test" name="x">'
                '<skipped message="no SQL Server on localhost:1435"/></testcase>'])
            self.assertEqual(skipped_for_want_of("sqlserver", directory, "seclume-sqlserver"), [])

    def test_the_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            report(directory, "seclume-oracle", [
                '<testcase classname="A" name="x"><skipped>no .local-oracle-password'
                '</skipped></testcase>'])
            here = os.getcwd()
            try:
                os.chdir(directory)
                # Captured: an "::error" line on the job's own output would be
                # an annotation on the pull request.
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(main(["", "oracle", "seclume-oracle"]), 1)
                    self.assertEqual(main(["", "sqlserver", "seclume-oracle"]), 0)
                    self.assertEqual(main(["", "db2", "seclume-oracle"]), 2)
                self.assertIn("::error title=skipped without its server::A.x", out.getvalue())
            finally:
                os.chdir(here)


if __name__ == "__main__":
    unittest.main()
