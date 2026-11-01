import unittest

from jmh_notices import lines, rows


def result(benchmark, score, error=1.0, unit="us/op", mode="avgt", **params):
    return {"benchmark": f"space.seclume.bench.{benchmark}", "mode": mode, "params": params,
            "primaryMetric": {"score": score, "scoreError": error, "scoreUnit": unit}}


class JmhNoticesTest(unittest.TestCase):
    def test_seclume_and_the_vendor_are_paired_with_the_ratio(self):
        found = rows([
            result("R2dbcContentionBenchmark.batch", 40.0, unit="ms/op", pool="seclume", requests="512"),
            result("R2dbcContentionBenchmark.batch", 50.0, unit="ms/op", pool="r2dbc-pool", requests="512"),
            result("R2dbcContentionBenchmark.batch", 9.0, unit="ms/op", pool="r2dbc-pool", requests="64"),
            result("R2dbcContentionBenchmark.batch", 12.0, unit="ms/op", pool="seclume", requests="64"),
        ])
        out = lines(found)
        self.assertEqual(2, len(out))
        self.assertTrue(out[0].startswith("R2dbcContentionBenchmark.batch [requests=512]: seclume 40.000"), out[0])
        self.assertIn("ratio 0.80 (seclume ahead)", out[0])
        self.assertIn("ratio 1.33 (seclume behind)", out[1])

    def test_throughput_is_better_when_higher(self):
        out = lines(rows([result("X.ops", 200.0, mode="thrpt", unit="ops/s", driver="seclume"),
                          result("X.ops", 100.0, mode="thrpt", unit="ops/s", driver="vendor")]))
        self.assertIn("ratio 2.00 (seclume ahead)", out[0])

    def test_a_benchmark_without_a_driver_is_listed_alone(self):
        out = lines(rows([result("Pbkdf2Benchmark.derive", 3.5, iterations="600000")]))
        self.assertEqual(["Pbkdf2Benchmark.derive [iterations=600000]: run 3.500 ± 1.000 us/op"], out)


if __name__ == "__main__":
    unittest.main()
