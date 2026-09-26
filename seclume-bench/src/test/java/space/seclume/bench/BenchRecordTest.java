package space.seclume.bench;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The control for a generated benchmark record.
 *
 * <p>A reader is going to take these numbers on trust, which is exactly the
 * reason not to. Three things have to be true of the page and none of them is
 * obvious from looking at one:
 *
 * <ol>
 *   <li>the score in the table is the score JMH reported, not a rounding of a
 *       rounding;
 *   <li>the <b>raw iterations</b> reach the page. An average with an error bar
 *       hides a bimodal result, and a bimodal result is usually the
 *       interesting one - a driver that is fast four times out of five and
 *       terrible the fifth time has an excellent mean;
 *   <li>the environment is on the page. A figure without the machine and the
 *       distance to the server is not reproducible, and this whole exercise is
 *       about it being reproducible.
 * </ol>
 *
 * <p>The JSON here is JMH's own shape, written out by hand, because the only
 * way to test a reader is to hand it something it did not produce.
 */
class BenchRecordTest {

    /** One benchmark, as JMH writes it - trimmed to the fields that are read. */
    private static final String JMH_JSON = """
            [
            {
                "jmhVersion" : "1.37",
                "benchmark" : "space.seclume.bench.QueryBenchmark.seclumeOneRow",
                "mode" : "avgt",
                "threads" : 1,
                "forks" : 2,
                "warmupIterations" : 3,
                "measurementIterations" : 5,
                "primaryMetric" : {
                    "score" : 0.245,
                    "scoreError" : 0.012,
                    "scoreUnit" : "ms/op",
                    "rawData" : [[0.241, 0.244, 0.246, 0.248, 0.9991]]
                }
            }
            ]
            """;

    private static Map<String, String> environment() {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("os", "Linux 6.8 (amd64)");
        facts.put("cpus", "8");
        facts.put("jdk", "OpenJDK 64-Bit Server VM 25");
        facts.put("server", "PostgreSQL 16.15");
        facts.put("round trip", "604 µs median of 80 round trips");
        return facts;
    }

    private static String page() {
        return BenchRecord.render(BenchRecord.parse(JMH_JSON), environment(),
                "java -jar seclume-bench.jar QueryBenchmark -rf json");
    }

    @Test
    void theScoreAndItsErrorReachThePage() {
        String page = page();
        assertTrue(page.contains("0.245"), "the score JMH reported is missing:\n" + page);
        assertTrue(page.contains("0.012"), "the error bar is missing:\n" + page);
        assertTrue(page.contains("ms/op"), "a number without its unit is not a number");
    }

    /**
     * The one that matters most.
     *
     * <p>The fixture's fifth iteration is four times the other four. A report
     * that printed only the mean would say 0.245 ms and be technically true
     * and practically a lie. The outlier has to be on the page, where somebody
     * can see it and ask why.
     */
    @Test
    void everyIterationReachesThePage() {
        String page = page();
        for (String iteration : new String[] {"0.241", "0.244", "0.246", "0.248", "0.999"}) {
            assertTrue(page.contains(iteration),
                    "iteration " + iteration + " was summarised away:\n" + page);
        }
    }

    @Test
    void theMachineAndTheDistanceAreOnThePage() {
        String page = page();
        assertTrue(page.contains("604 µs"),
                "the distance to the server is the single number that most changes a driver "
                + "benchmark, and it is missing:\n" + page);
        assertTrue(page.contains("PostgreSQL 16.15"), "which server answered is missing");
        assertTrue(page.contains("OpenJDK"), "which JDK ran it is missing");
    }

    @Test
    void theCommandThatMadeItIsOnThePage() {
        assertTrue(page().contains("java -jar seclume-bench.jar QueryBenchmark"),
                "the second most useful thing after a number is the command that makes it "
                + "again");
    }

    /**
     * And the control's control: a page built from nothing must not look like
     * a page built from a run.
     */
    @Test
    void anEmptyRunDoesNotLookLikeAResult() {
        String page = BenchRecord.render(BenchRecord.parse("[]"), environment(), "none");
        assertFalse(page.contains("ms/op"),
                "a record of no measurements should carry no measurements:\n" + page);
    }
}
