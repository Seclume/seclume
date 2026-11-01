import unittest

from summarize_flakes import classify, describe, group


def job(name, conclusion, failed_steps=()):
    steps = [{"name": "checkout", "conclusion": "success"}]
    steps += [{"name": s, "conclusion": "failure"} for s in failed_steps]
    return {"name": name, "conclusion": conclusion, "steps": steps}


class SummarizeFlakesTest(unittest.TestCase):
    def test_a_job_failing_in_some_runs_is_flaky_and_in_all_is_broken(self):
        raw = [
            job("run 1 / oracle", "success"),
            job("run 2 / oracle", "failure", ["Verify framework edge cases"]),
            job("run 3 / oracle", "success"),
            job("run 1 / mysql (8.4)", "failure", ["Run tests"]),
            job("run 2 / mysql (8.4)", "failure", ["Run tests"]),
            job("run 3 / mysql (8.4)", "timed_out"),
            job("run 1 / build", "success"),
            job("run 2 / build", "success"),
            job("run 3 / build", "success"),
        ]
        flaky, broken = classify(group(raw))
        self.assertEqual(["oracle"], flaky)
        self.assertEqual(["mysql (8.4)"], broken)

    def test_jobs_outside_the_repeated_runs_are_ignored(self):
        jobs = group([job("summary", "failure"), job("run 1 / build", "success")])
        self.assertEqual(["build"], list(jobs))

    def test_the_description_names_each_run_and_the_steps_that_failed(self):
        jobs = group([job("run 2 / oracle", "failure", ["Verify framework edge cases"]),
                      job("run 1 / oracle", "success")])
        self.assertEqual("oracle - run 1: success, run 2: failure (Verify framework edge cases)",
                         describe("oracle", jobs["oracle"]))

    def test_skipped_and_cancelled_runs_are_neither(self):
        jobs = group([job("run 1 / x", "skipped"), job("run 2 / x", "cancelled"), job("run 3 / x", "success")])
        self.assertEqual(([], []), classify(jobs))

    def test_a_job_name_with_a_slash_keeps_it(self):
        jobs = group([job("run 1 / security-platforms (linux / arm64)", "failure")])
        self.assertEqual(["security-platforms (linux / arm64)"], list(jobs))


if __name__ == "__main__":
    unittest.main()
