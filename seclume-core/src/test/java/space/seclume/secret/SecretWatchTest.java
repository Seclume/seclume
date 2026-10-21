package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A secret replaced at its source is noticed once, and nothing else counts as
 * a change: not a second look at the same secret, not a moment in which the
 * source cannot be read.
 */
@org.junit.jupiter.api.parallel.Isolated
class SecretWatchTest {

    @TempDir
    Path directory;

    private SecretProvider file(Path path) {
        return SecretProviders.of(Map.of("provider", "file", "path", path.toString()));
    }

    /** As the kubelet does it: the new content arrives by rename. */
    private void replace(Path secret, String content) throws Exception {
        Path next = directory.resolve("next");
        Files.writeString(next, content);
        Files.move(next, secret, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
    }

    @Test
    void aChangeIsSeenOnceAndNothingElseIsAChange() throws Exception {
        Path secret = directory.resolve("password");
        Files.writeString(secret, "first-password");
        AtomicInteger rotations = new AtomicInteger();
        try (SecretWatch watch = SecretWatch.start("orders-db", file(secret), Duration.ofHours(1),
                rotations::incrementAndGet)) {
            assertFalse(watch.checkNow(), "nothing changed yet");

            replace(secret, "second-password");
            assertTrue(watch.checkNow());
            assertFalse(watch.checkNow(), "the same rotation counted twice");
            assertEquals(1, rotations.get());

            // the source gone for a moment is not a rotation ...
            Files.delete(secret);
            assertFalse(watch.checkNow());
            // ... and the same secret back is not one either
            Files.writeString(secret, "second-password");
            assertFalse(watch.checkNow());
            replace(secret, "third-password");
            assertTrue(watch.checkNow());
            assertEquals(2, rotations.get());
            assertEquals(2, watch.changes());
        }
    }

    @Test
    void theTicksFindARotationOnTheirOwn() throws Exception {
        Path secret = directory.resolve("token");
        Files.writeString(secret, "token-one");
        CountDownLatch rotated = new CountDownLatch(1);
        try (SecretWatch watch = SecretWatch.start("api", file(secret), Duration.ofMillis(50),
                rotated::countDown)) {
            replace(secret, "token-two");
            assertTrue(rotated.await(10, TimeUnit.SECONDS), "the watch never noticed");
            assertEquals(1, watch.changes());
        }
    }

    @Test
    void aFailingConsumerIsReportedAndTheWatchGoesOn() throws Exception {
        Path secret = directory.resolve("key");
        Files.writeString(secret, "k1");
        Path recorded = directory.resolve("rotation.jfr");
        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.SecretRotation");
            recording.start();
            AtomicInteger calls = new AtomicInteger();
            try (SecretWatch watch = SecretWatch.start("tls-key", file(secret),
                    Duration.ofHours(1), () -> {
                        if (calls.incrementAndGet() == 1) {
                            throw new IllegalStateException("the new key does not match");
                        }
                    })) {
                replace(secret, "k2");
                assertTrue(watch.checkNow());
                replace(secret, "k3");
                assertTrue(watch.checkNow());
            }
            recording.stop();
            recording.dump(recorded);
        }
        List<RecordedEvent> events = RecordingFile.readAllEvents(recorded).stream()
                .filter(e -> e.getEventType().getName().equals("space.seclume.SecretRotation"))
                .toList();
        assertEquals(2, events.size(), events.toString());
        assertEquals("tls-key", events.get(0).getString("watch"));
        assertFalse(events.get(0).getBoolean("succeeded"));
        assertTrue(events.get(0).getString("reason").contains("does not match"));
        assertTrue(events.get(1).getBoolean("succeeded"));
    }

    @Test
    void aClosedWatchSeesNothing() throws Exception {
        Path secret = directory.resolve("s");
        Files.writeString(secret, "one");
        AtomicInteger rotations = new AtomicInteger();
        SecretWatch watch = SecretWatch.start("x", file(secret), Duration.ofHours(1),
                rotations::incrementAndGet);
        watch.close();
        replace(secret, "two");
        assertFalse(watch.checkNow());
        assertEquals(0, rotations.get());
    }

    /**
     * A source that cannot be read is reported once, not at every look, and
     * once again when it can be read; a rotation taken up says so. The log is
     * what an operator sees - a warning per tick would bury the rest.
     */
    @Test
    void anUnreadableSourceIsReportedOnceAndItsReturnToo() throws Exception {
        Path secret = directory.resolve("s");
        Files.writeString(secret, "one");
        java.util.logging.Logger jul = java.util.logging.Logger.getLogger(
                SecretWatch.class.getName());
        List<java.util.logging.LogRecord> records =
                java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            @Override
            public void publish(java.util.logging.LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        java.util.logging.Level before = jul.getLevel();
        jul.setLevel(java.util.logging.Level.ALL);
        jul.addHandler(handler);
        try (SecretWatch watch = SecretWatch.start("db", file(secret), Duration.ofHours(1),
                () -> { })) {
            Files.delete(secret);
            assertFalse(watch.checkNow());
            assertFalse(watch.checkNow());
            assertFalse(watch.checkNow());
            replace(secret, "one");
            assertFalse(watch.checkNow(), "the same secret back is no rotation");
            assertFalse(watch.checkNow());
            replace(secret, "two");
            assertTrue(watch.checkNow());
        } finally {
            jul.removeHandler(handler);
            jul.setLevel(before);
        }
        List<String> seen = records.stream()
                .map(r -> r.getLevel() + " " + r.getMessage()).toList();
        assertEquals(3, seen.size(), seen.toString());
        assertTrue(seen.get(0).startsWith("WARNING the secret for db cannot be read"), seen.get(0));
        assertTrue(seen.get(1).startsWith("INFO the secret for db can be read again"), seen.get(1));
        assertTrue(seen.get(2).startsWith("INFO the secret for db was rotated"), seen.get(2));
    }

    @Test
    void anIntervalOfZeroIsRefused() throws Exception {
        Path secret = directory.resolve("s");
        Files.writeString(secret, "one");
        assertThrows(IllegalArgumentException.class, () -> SecretWatch.start("x", file(secret),
                Duration.ZERO, () -> { }));
    }
}
