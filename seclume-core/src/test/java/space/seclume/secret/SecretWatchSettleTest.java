package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * A secret file rewritten in place - echo new > file - can be read half
 * written. The watch reported that half as the rotation, and the pool logged
 * in with half a password: a failed login, on Oracle or MySQL a locked
 * account. A change is believed when it reads the same a moment later.
 */
class SecretWatchSettleTest {

    /** A source that answers what it is told to, one read at a time, then the last again. */
    private static final class Reads implements SecretProvider {
        final Deque<String> next = new ArrayDeque<>();
        String last;

        @Override
        public synchronized int writeSecret(MemorySegment target) {
            if (!next.isEmpty()) {
                last = next.poll();
            }
            byte[] bytes = last.getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        }

        @Override
        public int maxSecretLength() {
            return 64;
        }
    }

    @Test
    void halfAWrittenSecretIsNotARotation() {
        Reads source = new Reads();
        source.next.add("first-password");
        AtomicInteger rotations = new AtomicInteger();
        try (SecretWatch watch = SecretWatch.start("orders-db", source, Duration.ofHours(1),
                rotations::incrementAndGet)) {
            assertFalse(watch.checkNow());
            source.next.add("second-pa");                 // read while being written
            source.next.add("second-password");           // and done a moment later
            assertFalse(watch.checkNow(), "half a password was taken up");
            assertEquals(0, rotations.get());
            assertTrue(watch.checkNow(), "the whole one is a rotation");
            assertEquals(1, rotations.get());
        }
    }
}
