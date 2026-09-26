package space.seclume.bench;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The nightly regression check: ratios from one run, compared with a
 * baseline, with the two ways to fail and the two ways not to.
 */
class BenchRegressionTest {

    /** A result in JMH's shape; {@code side} is the driver parameter. */
    private static String result(String method, String side, double score) {
        return """
                {
                    "jmhVersion" : "1.37",
                    "benchmark" : "space.seclume.bench.QueryBenchmark.%s",
                    "mode" : "avgt",
                    "forks" : 1,
                    "warmupIterations" : 3,
                    "measurementIterations" : 5,
                    "params" : {
                        "driver" : "%s",
                        "rows" : "1000"
                    },
                    "primaryMetric" : {
                        "score" : %s,
                        "scoreError" : 0.1,
                        "scoreUnit" : "us/op",
                        "rawData" : [[1.0, 1.0]]
                    }
                }""".formatted(method, side, Double.toString(score));
    }

    private static Map<String, Double> run(double seclumeOne, double vendorOne,
                                           double seclumeMany, double vendorMany) {
        String json = "[" + String.join(",", result("selectRow", "seclume", seclumeOne),
                result("selectRow", "vendor", vendorOne),
                result("selectManyRows", "seclume", seclumeMany),
                result("selectManyRows", "vendor", vendorMany)) + "]";
        return BenchRegression.ratios(BenchRecord.parse(json));
    }

    private static final String BASELINE = """
            # a comment
            tolerance=0.15
            QueryBenchmark.selectRow [rows=1000]=0.90
            QueryBenchmark.selectManyRows [rows=1000]=0.80
            InsertBenchmark.batch [rows=500]=0.62
            """;

    @Test
    void theRatioPairsTheTwoDriversOfTheSameWorkload() {
        Map<String, Double> ratios = run(45, 50, 700, 1000);
        assertEquals(0.9, ratios.get("QueryBenchmark.selectRow [rows=1000]"), 1e-9);
        assertEquals(0.7, ratios.get("QueryBenchmark.selectManyRows [rows=1000]"), 1e-9);
        assertEquals(2, ratios.size());
    }

    /** A slower runner makes both sides slower: the ratio stays, and nothing fails. */
    @Test
    void aSlowerRunnerIsNotARegression() {
        BenchRegression.Report report = BenchRegression.compare(BASELINE,
                run(45 * 1.6, 50 * 1.6, 800 * 1.6, 1000 * 1.6));
        assertFalse(report.failed(), String.join("\n", report.lines()));
        assertTrue(report.lines().stream().anyMatch(l -> l.contains("not measured")
                && l.contains("InsertBenchmark.batch")), "the unmeasured pair is reported");
    }

    @Test
    void seclumeFallingBehindItsOwnRatioIsARegression() {
        // selectManyRows 0.80 -> 0.95: still ahead, but 19 % worse.
        BenchRegression.Report report = BenchRegression.compare(BASELINE,
                run(45, 50, 950, 1000));
        assertTrue(report.failed());
        assertTrue(report.lines().stream().anyMatch(l -> l.contains("REGRESSED")
                && l.contains("selectManyRows")), String.join("\n", report.lines()));
    }

    @Test
    void losingAClearLeadFailsEvenWithinTheTolerance() {
        // selectRow 0.90 -> 1.01: within 15 %, but "faster" is no longer true.
        BenchRegression.Report report = BenchRegression.compare(BASELINE,
                run(50.5, 50, 800, 1000));
        assertTrue(report.failed());
        assertTrue(report.lines().stream().anyMatch(l -> l.contains("LOST LEAD")),
                String.join("\n", report.lines()));
    }

    @Test
    void aLeadWithinTheNoiseIsNotAClaimToLose() {
        String baseline = "QueryBenchmark.selectRow [rows=1000]=0.99\n";
        BenchRegression.Report report = BenchRegression.compare(baseline,
                run(51, 50, 800, 1000));
        assertFalse(report.failed(), String.join("\n", report.lines()));
        assertTrue(report.lines().stream().anyMatch(l -> l.contains("new")
                && l.contains("selectManyRows")), "an unknown pair is reported as new");
    }
}
