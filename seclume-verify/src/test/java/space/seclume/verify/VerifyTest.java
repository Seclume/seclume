package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;

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
        assertFalse(text.contains("TLS failed"), "that was not a TLS problem:\n" + text);
    }

    /**
     * A refused certificate is not an unreachable server.
     *
     * <p>Both arrive as SQLState 08, and the advice for 08 sends the reader to
     * check host, port and firewall - none of which is the problem when the
     * server answered and only its certificate was not accepted. That happened
     * for real against a test container, and cost a while.
     */
    @Test
    void aRefusedCertificateSaysSoInsteadOfBlamingTheNetwork() {
        SQLException failure = new SQLException("the login to db.example failed", "08001",
                new javax.net.ssl.SSLHandshakeException(
                        "PKIX path building failed: unable to find valid certification path"));
        assertTrue(Verify.isTlsFailure(failure));
        String advice = Verify.advice(failure);
        assertTrue(advice.contains("TLS failed"), advice);
        assertTrue(advice.contains("certificate"), advice);
        assertFalse(advice.contains("firewall"),
                "that advice belongs to a server nobody reached: " + advice);
    }

    /** And the other way round: a plain connection failure keeps its own advice. */
    @Test
    void aConnectionFailureWithoutTlsKeepsTheNetworkAdvice() {
        SQLException failure = new SQLException("cannot reach db.example:5432", "08001",
                new java.net.ConnectException("Connection refused"));
        assertFalse(Verify.isTlsFailure(failure));
        assertTrue(Verify.advice(failure).contains("firewall"), Verify.advice(failure));
    }

    /** A TLS failure buried deeper than one level is still found. */
    @Test
    void theWholeChainIsSearched() {
        SQLException failure = new SQLException("the login failed", "08001",
                new java.io.IOException("handshake",
                        new javax.net.ssl.SSLException("certificate unknown")));
        assertTrue(Verify.isTlsFailure(failure));
    }

    /**
     * A URL the driver refuses is not a network problem.
     *
     * <p>Found by reading this tool's own JSON output: a URL carrying
     * {@code password=} came back with state {@code 08001} and the advice
     * "check host, port and firewall". All three were fine and no server had
     * been asked. The state was right and the sentence sent somebody to the
     * wrong place, which is the worse of the two failures a diagnostic can
     * have.
     */
    @Test
    void aRefusedSettingIsNotReportedAsANetworkProblem() {
        Report report = new Report();
        assertEquals(1, Verify.run(
                "jdbc:seclume:postgresql://127.0.0.1:1/db?user=app&password=hunter2", report));
        String text = report.toString();
        assertTrue(text.contains("refused before any server was asked"), text);
        assertFalse(text.contains("firewall"),
                "the network advice would send somebody checking three things that are "
                        + "fine: " + text);
    }
}
