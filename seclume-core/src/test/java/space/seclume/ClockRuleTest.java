package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The source rule against comparing nanoTime readings with {@code <} or
 * {@code >}, and against the wall clock: both forms are caught, the
 * difference is not, and an allow marker with its reason lets one through.
 */
class ClockRuleTest {

    @Test
    void aDirectComparisonAndTheWallClockAreCaught() {
        List<String> findings = new ArrayList<>();
        ForbiddenApiTest.check("A.java",
                "class A { boolean f(long d) { return System.nanoTime() > d; }\n"
                        + "boolean g(long d) { return d >= System.nanoTime(); }\n"
                        + "boolean h(long d) { return d - System.nanoTime() > 0; }\n"
                        + "long i() { return System.currentTimeMillis(); }\n"
                        + "long j() { return System.currentTimeMillis(); } // seclume-allow: by contract\n"
                        + "}", findings);
        assertEquals(3, findings.size(), findings.toString());
    }
}
