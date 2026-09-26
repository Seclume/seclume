package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The control for a generated table, and the reason the table is worth
 * reading.
 *
 * <p>A generator that printed {@code verified} in every cell would produce a
 * page indistinguishable from a correct one, and nobody would ever look twice.
 * So each of the four things a cell can say gets a test, built from reports
 * written here rather than from a run - which is also the only way to test the
 * outcomes a healthy run never produces.
 *
 * <p>This is the same lesson as Oracle's recycled {@code SID} and SQL Server's
 * {@code @@SPID} two days ago, in a third place: <b>a green table whose
 * control cannot go red is decoration.</b>
 */
class FrameworkMatrixTest {

    private static Map<String, FrameworkMatrix.Outcome> reports() {
        Map<String, FrameworkMatrix.Outcome> reports = new LinkedHashMap<>();
        // Passed.
        reports.put("SpringDataOnPostgresTest", FrameworkMatrix.outcome(12, 0, 0));
        // Ran and failed.
        reports.put("SpringDataOnMySqlTest", FrameworkMatrix.outcome(12, 3, 0));
        // Every test skipped - in this project, the server was not running.
        reports.put("SpringDataOnSqlServerTest", FrameworkMatrix.outcome(12, 0, 12));
        // SpringDataOnOracleTest deliberately absent.
        // Partly skipped - a gap named on one server.
        reports.put("HibernateEdgesOnOracleTest", FrameworkMatrix.outcome(5, 0, 3));
        return reports;
    }

    /** Partly skipped is shown as such, not quietly counted as verified. */
    @Test
    void aPartlySkippedClassSaysHowMuchWasSkipped() {
        assertTrue(FrameworkMatrix.renderFrom(reports()).contains("verified (2), 3 skipped"),
                "skipped cases are gaps and have to be visible in the cell");
    }

    @Test
    void aPassingClassIsVerifiedWithItsCount() {
        assertTrue(FrameworkMatrix.renderFrom(reports()).contains("verified (12)"),
                "a class that ran and passed should say so, with how much it ran");
    }

    /**
     * The most important of the four.
     *
     * <p>A table that quietly dropped a failure would be worse than no table:
     * it would be a document asserting something the run had just disproved.
     */
    @Test
    void aFailingClassIsSaidToHaveFailed() {
        String page = FrameworkMatrix.renderFrom(reports());
        assertTrue(page.contains("**failed** (3 of 12)"),
                "a failure has to reach the page, and say how much of it failed:\n" + page);
    }

    @Test
    void anEntirelySkippedClassIsNotCalledVerified() {
        String page = FrameworkMatrix.renderFrom(reports());
        assertTrue(page.contains("not verified - server absent"),
                "tests that were all skipped prove nothing and must not read as proof");
    }

    /**
     * And the cell the whole class exists for.
     *
     * <p>Nobody wrote {@code SpringDataOnOracleTest} in this fixture, and
     * this fixture has no report for Liquibase at all. Both come out the same way,
     * and the word is not "probably".
     */
    @Test
    void whatNobodyTestedIsUnsupported() {
        String page = FrameworkMatrix.renderFrom(reports());
        assertTrue(page.contains("unsupported"),
                "a framework nobody has run has to be named as such");
        long unsupported = page.lines()
                .filter(line -> line.startsWith("| **"))
                .mapToLong(line -> line.split("unsupported", -1).length - 1)
                .sum();
        // Three frameworks with no test at all, across four servers, plus the
        // Oracle cell of each of the three that do have one.
        assertTrue(unsupported >= 3 * 4 + 3,
                "expected every untested cell to say so; the page said it "
                + unsupported + " times:\n" + page);
    }
}
