package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The part that has to be right even with no server anywhere near: what goes
 * into the report, and above all what does not.
 */
class VerifyTest {

    /**
     * A password has no business being in a URL - and if somebody put one
     * there anyway, it does not travel on into a ticket.
     */
    @Test
    void aPasswordInTheUrlIsTakenOutOfTheReport() {
        String url = "jdbc:seclume:postgresql://db:5432/app?user=app&password=hunter2&x=1";
        String shown = Verify.withoutSecrets(url);
        assertFalse(shown.contains("hunter2"), shown);
        assertTrue(shown.contains("password=***"), shown);
        assertTrue(shown.contains("user=app"), shown);
        assertTrue(shown.contains("x=1"), shown);
    }

    @Test
    void aUrlWithoutOptionsIsLeftAlone() {
        String url = "jdbc:seclume:mysql://db:3306/app";
        assertEquals(url, Verify.withoutSecrets(url));
    }

    /** A URL no driver takes ends in a report, not in a stack trace. */
    @Test
    void anUnknownUrlIsReportedRatherThanThrown() {
        Report report = new Report();
        assertEquals(1, Verify.run("jdbc:something:else://host/db", report));
        assertTrue(report.toString().contains("no seclume driver"), report.toString());
        assertTrue(report.hasProblems());
    }

    /** A server that is not there: the report says what to try next. */
    @Test
    void anUnreachableServerIsReportedWithAdvice() {
        Report report = new Report();
        assertEquals(1, Verify.run(
                "jdbc:seclume:postgresql://127.0.0.1:1/app?user=app&provider=env&name=NOPE",
                report));
        String text = report.toString();
        assertTrue(text.contains("what to do"), text);
        assertTrue(text.contains("failed"), text);
    }
}
