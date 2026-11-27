package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.SecretProvider;

/**
 * After a restore the first line masked read every secret again - on the
 * logging thread, inside the masker's lock: a vault that took its time held
 * every thread that logged. The secrets are read on a thread of their own;
 * a line waits a bounded while for them, and one that cannot be checked by
 * then is withheld, not written unmasked.
 */
@Timeout(30)
class RestoreOffTheLogThreadTest {

    private static final byte[] SECRET = "restored-Pa55word".getBytes(StandardCharsets.UTF_8);

    /** A provider that, once told to, waits for a gate before it answers. */
    private static final class SlowProvider implements SecretProvider {
        volatile CountDownLatch gate;
        final AtomicReference<String> readOn = new AtomicReference<>();

        @Override
        public int writeSecret(MemorySegment target) {
            readOn.set(Thread.currentThread().getName());
            CountDownLatch waitFor = gate;
            if (waitFor != null) {
                try {
                    waitFor.await(20, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            MemorySegment.copy(SECRET, 0, target, ValueLayout.JAVA_BYTE, 0, SECRET.length);
            return SECRET.length;
        }

        @Override
        public int maxSecretLength() {
            return 64;
        }
    }

    @Test
    void aSlowReadingWithholdsTheLineAndRunsOffTheLogThread() throws Exception {
        SlowProvider provider = new SlowProvider();
        try (SecretMasker masker = new SecretMasker(Map.of("db", provider))) {
            assertEquals("x [redacted:db]", masker.mask("x restored-Pa55word"));
            space.seclume.internal.Checkpoint.wipeAll();
            provider.gate = new CountDownLatch(1);
            long started = System.nanoTime();
            assertEquals(SecretMasker.WITHHELD, masker.mask("x restored-Pa55word"),
                    "a line the masker could not check yet went out");
            long waited = (System.nanoTime() - started) / 1_000_000;
            assertTrue(waited >= SecretMasker.RESTORE_WAIT_MILLIS - 100
                    && waited < SecretMasker.RESTORE_WAIT_MILLIS + 3000, waited + " ms");
            assertEquals("seclume-log-restore", provider.readOn.get(),
                    "the secrets were read on the logging thread");
            provider.gate.countDown();
            provider.gate = null;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            String masked;
            do {
                masked = masker.mask("x restored-Pa55word");
            } while (!masked.equals("x [redacted:db]") && System.nanoTime() < deadline);
            assertEquals("x [redacted:db]", masked);
        }
    }

    /** A refresh due after a restore, before any line, starts the reading the restore needs. */
    @Test
    void aRefreshAfterARestoreReadsUnderANewKey() throws Exception {
        SlowProvider provider = new SlowProvider();
        try (SecretMasker masker = new SecretMasker(Map.of("db", provider))) {
            space.seclume.internal.Checkpoint.wipeAll();
            assertEquals(0, masker.forms());
            masker.refresh();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (masker.forms() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertEquals("x [redacted:db]", masker.mask("x restored-Pa55word"));
        }
    }
}
