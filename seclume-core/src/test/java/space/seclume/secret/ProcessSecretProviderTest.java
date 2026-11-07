package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import space.seclume.Segments;

@EnabledOnOs({OS.LINUX, OS.MAC})
@Timeout(30)
class ProcessSecretProviderTest {
    @Test
    void helperOutputStillArrivesThroughTheFifo() {
        ProcessSecretProvider provider = new ProcessSecretProvider(
                List.of("/bin/sh", "-c", "printf 'fifo-test-secret\\n' > \"$1\"",
                        "fifo-helper", "{fifo}"), 64);
        try (SecretScope scope = SecretScope.fromProvider(provider)) {
            assertEquals("fifo-test-secret", new String(Segments.toBytes(scope.secret()),
                    java.nio.charset.StandardCharsets.US_ASCII));
        }
    }

    /**
     * Without {@code {fifo}} the helper's standard output is the FIFO - the
     * form of {@code aws secretsmanager get-secret-value ...}. This JVM opens
     * the write end for it, inside {@code ProcessBuilder.start()}, and before
     * the read end was opened first that waited for a reader for ever: the
     * form never worked.
     */
    @Test
    void helperStandardOutputArrivesThroughTheFifo() {
        ProcessSecretProvider provider = new ProcessSecretProvider(
                List.of("/bin/sh", "-c", "printf 'stdout-secret\\n'"), 64, 20);
        long started = System.nanoTime();
        try (SecretScope scope = SecretScope.fromProvider(provider)) {
            assertEquals("stdout-secret", new String(Segments.toBytes(scope.secret()),
                    java.nio.charset.StandardCharsets.US_ASCII));
        }
        assertTrue(System.nanoTime() - started < 10_000_000_000L, "it waited");
    }

    /** A command that is not there: refused at once, and the FIFO's opener let go. */
    @Test
    void aHelperThatIsNotThereIsRefusedAtOnce() {
        SecretUnavailableException e = refused(new ProcessSecretProvider(
                List.of("/nonexistent/seclume-helper", "{fifo}"), 64, 20), 10_000);
        assertTrue(e.getMessage().contains("cannot run /nonexistent/seclume-helper"),
                e.getMessage());
    }

    private static SecretUnavailableException refused(ProcessSecretProvider provider,
            long withinMillis) {
        long started = System.nanoTime();
        SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                () -> SecretScope.fromProvider(provider).close());
        long took = (System.nanoTime() - started) / 1_000_000;
        assertTrue(took < withinMillis, "took " + took + " ms: " + e.getMessage());
        return e;
    }

    /**
     * A helper that fails before it opens the path it was given: the read of
     * the FIFO waited for a writer that never came - for ever, not for the
     * timeout, which was only looked at afterwards.
     */
    @Test
    void aHelperThatFailsBeforeOpeningItsFifoIsReportedNotWaitedFor() {
        SecretUnavailableException e = refused(new ProcessSecretProvider(
                List.of("/bin/sh", "-c", "exit 3", "fifo-helper", "{fifo}"), 64, 20), 10_000);
        assertTrue(e.getMessage().contains("failed with exit code 3"), e.getMessage());
    }

    /** A helper that never finishes is ended at the timeout, not when it pleases. */
    @Test
    void aHelperThatNeverFinishesIsEndedAtTheTimeout() {
        SecretUnavailableException e = refused(new ProcessSecretProvider(
                List.of("/bin/sh", "-c", "exec sleep 60"), 64, 1), 15_000);
        assertTrue(e.getMessage().contains("did not finish within 1 seconds"), e.getMessage());
    }

    /** Also when it has opened the FIFO and hands it to a child that keeps it open. */
    @Test
    void aHelperWhoseChildKeepsTheFifoOpenIsEndedAtTheTimeoutToo() {
        SecretUnavailableException e = refused(new ProcessSecretProvider(
                List.of("/bin/sh", "-c", "printf 'part'; sleep 60 & wait"), 64, 1), 15_000);
        assertTrue(e.getMessage().contains("did not finish within 1 seconds"), e.getMessage());
    }

    /** And with the FIFO named: the helper that opens it and then sits there. */
    @Test
    void aHelperThatOpensTheNamedFifoAndWaitsIsEndedAtTheTimeout() {
        SecretUnavailableException e = refused(new ProcessSecretProvider(
                List.of("/bin/sh", "-c", "exec 3>\"$1\"; exec sleep 60", "fifo-helper", "{fifo}"),
                64, 1), 15_000);
        assertTrue(e.getMessage().contains("did not finish within 1 seconds"), e.getMessage());
    }

    @Test
    void aHelperThatProducesNothingSaysSo() {
        SecretUnavailableException e = refused(new ProcessSecretProvider(
                List.of("/bin/sh", "-c", "true"), 64, 10), 10_000);
        assertTrue(e.getMessage().contains("produced nothing"), e.getMessage());
    }
}
