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

    def test_the_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            report(directory, "seclume-oracle", [
                '<testcase classname="A" name="x"><skipped>no .local-oracle-password'
                '</skipped></testcase>'])
            here = os.getcwd()
            try:
                os.chdir(directory)
                self.assertEqual(main(["", "oracle", "seclume-oracle"]), 1)
                self.assertEqual(main(["", "sqlserver", "seclume-oracle"]), 0)
                self.assertEqual(main(["", "db2", "seclume-oracle"]), 2)
            finally:
                os.chdir(here)


if __name__ == "__main__":
    unittest.main()
