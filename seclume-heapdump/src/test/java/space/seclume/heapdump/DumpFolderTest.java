package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A folder as {@code -XX:HeapDumpPath} leaves it: finished dumps are redacted
 * and gone, one still being written is left alone, a copy never takes the
 * name the next dump of the same pid will want.
 */
class DumpFolderTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static String alnum(int length) {
        String letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            out.append(letters.charAt(RANDOM.nextInt(letters.length())));
        }
        return out.toString();
    }

    /** A finished dump holding a GitHub token in a byte[]; or unfinished, without the end record. */
    private static byte[] dump(String token, boolean finished) {
        TestHprof h = new TestHprof(8);
        h.byteArray(0x500, token.getBytes(StandardCharsets.US_ASCII), new long[1]);
        h.finish();
        if (finished) {
            h.end();
        }
        return h.file.toByteArray();
    }

    private static boolean contains(byte[] data, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static List<String> names(Path folder) throws IOException {
        try (Stream<Path> files = Files.list(folder)) {
            return files.map(f -> f.getFileName().toString()).sorted().toList();
        }
    }

    @Test
    void aFinishedDumpIsRedactedNextToItselfAndThenGone(@TempDir Path folder) throws IOException {
        String body = alnum(36);
        Path dump = Files.write(folder.resolve("java_pid1.hprof"), dump("ghp_" + body, true));
        Files.setLastModifiedTime(dump, FileTime.from(Instant.parse("2026-10-30T00:15:00Z")));

        List<DumpFolder.Outcome> outcomes = DumpFolder.redactAll(folder,
                DumpFolder.Settings.discovery(Set.of()));

        assertEquals(1, outcomes.size());
        DumpFolder.Outcome outcome = outcomes.get(0);
        assertTrue(outcome.ok(), outcome.describe());
        assertEquals(List.of("java_pid1-20261030T001500Z.redacted.hprof"), names(folder),
                "the original is still there, or the copy has another name");
        byte[] copy = Files.readAllBytes(outcome.redacted());
        assertFalse(contains(copy, body.getBytes(StandardCharsets.US_ASCII)));
        assertTrue(DumpFolder.complete(outcome.redacted()), "the copy is a dump no more");
        assertFalse(outcome.describe().contains(body), outcome.describe());
        // A redacted copy is not taken for a dump the next time.
        assertEquals(List.of(), DumpFolder.redactAll(folder,
                DumpFolder.Settings.discovery(Set.of())));
    }

    @Test
    void theNextDumpOfTheSamePidFindsItsNameFreeAndItsCopyANewOne(@TempDir Path folder)
            throws IOException {
        Instant when = Instant.parse("2026-10-30T00:15:00Z");
        for (int round = 0; round < 2; round++) {
            Path dump = Files.write(folder.resolve("java_pid1.hprof"),
                    dump("ghp_" + alnum(36), true));
            Files.setLastModifiedTime(dump, FileTime.from(when));
            assertTrue(DumpFolder.redactAll(folder, DumpFolder.Settings.discovery(Set.of()))
                    .get(0).ok());
        }
        assertEquals(List.of("java_pid1-20261030T001500Z-2.redacted.hprof",
                "java_pid1-20261030T001500Z.redacted.hprof"), names(folder));
    }

    /** HotSpot's own dump ends with the record looked for, and a cut one does not. */
    @Test
    void aRealDumpIsFinishedOnlyWhenWrittenToItsEnd(@TempDir Path folder) throws IOException {
        Path dump = folder.resolve("self.hprof");
        java.lang.management.ManagementFactory.getPlatformMXBean(
                com.sun.management.HotSpotDiagnosticMXBean.class).dumpHeap(dump.toString(), true);
        assertTrue(DumpFolder.complete(dump));
        Path cut = folder.resolve("cut.hprof");
        try (var in = Files.newInputStream(dump); var out = Files.newOutputStream(cut)) {
            out.write(in.readNBytes((int) Math.min(Files.size(dump) - 1, 1 << 20)));
        }
        assertFalse(DumpFolder.complete(cut));
    }

    @Test
    void aDumpStillBeingWrittenIsLeftAlone(@TempDir Path folder) throws IOException {
        byte[] whole = dump("ghp_" + alnum(36), true);
        Path dump = Files.write(folder.resolve("java_pid7.hprof"),
                Arrays.copyOf(whole, whole.length - 9));
        assertFalse(DumpFolder.complete(dump));
        assertEquals(List.of(), DumpFolder.redactAll(folder,
                DumpFolder.Settings.discovery(Set.of())));
        assertEquals(List.of("java_pid7.hprof"), names(folder));
        Files.writeString(folder.resolve("notes.hprof"), "not a dump at all");
        assertFalse(DumpFolder.complete(folder.resolve("notes.hprof")));
    }

    @Test
    void aDumpThatCannotBeMadeCleanIsKeptOrDeletedAsSaid(@TempDir Path folder)
            throws IOException {
        // A token in a file with an end record but no readable structure: found,
        // and the String hashes cannot be looked for - so no copy.
        byte[] raw = ("JAVA PROFILE 1.0.2\0 ghp_" + alnum(36) + " ")
                .getBytes(StandardCharsets.US_ASCII);
        byte[] broken = Arrays.copyOf(raw, raw.length + 9);
        broken[raw.length] = 0x2c;
        Path dump = Files.write(folder.resolve("java_pid3.hprof"), broken);
        DumpFolder.Outcome kept = DumpFolder.redactAll(folder,
                DumpFolder.Settings.discovery(Set.of())).get(0);
        assertFalse(kept.ok());
        assertFalse(kept.deleted());
        assertTrue(Files.exists(dump));
        assertTrue(kept.describe().contains("still holds its secrets"), kept.describe());

        DumpFolder.Outcome deleted = DumpFolder.redactAll(folder,
                new DumpFolder.Settings(List.of(), true, Set.of(), true)).get(0);
        assertFalse(deleted.ok());
        assertTrue(deleted.deleted());
        assertEquals(List.of(), names(folder), "the dump or a partial copy is still there");
    }

    @Test
    void aStalePartialCopyIsRemovedAFreshOneIsNot(@TempDir Path folder) throws IOException {
        Path stale = Files.writeString(folder.resolve(".seclume-redact-1.hprof.part"), "old");
        Files.setLastModifiedTime(stale, FileTime.from(Instant.now().minus(Duration.ofHours(2))));
        Path fresh = Files.writeString(folder.resolve(".seclume-redact-2.hprof.part"), "new");
        DumpFolder.redactAll(folder, DumpFolder.Settings.discovery(Set.of()));
        assertFalse(Files.exists(stale));
        assertTrue(Files.exists(fresh), "a redaction in progress lost its copy");
    }

    /** Watching: a dump is taken once it is finished and has stopped growing - and a failure is said once. */
    @Test
    void theWatchTakesADumpOnceItHasStoppedGrowing(@TempDir Path folder) throws Exception {
        List<DumpFolder.Outcome> outcomes = new CopyOnWriteArrayList<>();
        try (DumpFolder.Watch watch = DumpFolder.watch(folder,
                DumpFolder.Settings.discovery(Set.of()), Duration.ofHours(1), outcomes::add)) {
            byte[] whole = dump("ghp_" + alnum(36), true);
            Path dump = folder.resolve("java_pid9.hprof");
            Files.write(dump, Arrays.copyOf(whole, whole.length / 2));
            assertEquals(0, watch.checkNow(), "half a dump was taken");
            Files.write(dump, whole);
            assertEquals(0, watch.checkNow(), "taken while it had just grown");
            assertEquals(1, watch.checkNow(), "a finished dump that stopped growing was left");
            assertTrue(outcomes.get(outcomes.size() - 1).ok());
            assertTrue(names(folder).stream().allMatch(n -> n.endsWith(".redacted.hprof")));

            byte[] raw = ("JAVA PROFILE 1.0.2\0 ghp_" + alnum(36) + " ")
                    .getBytes(StandardCharsets.US_ASCII);
            byte[] broken = Arrays.copyOf(raw, raw.length + 9);
            broken[raw.length] = 0x2c;
            Files.write(folder.resolve("java_pid10.hprof"), broken);
            List<Integer> takes = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                takes.add(watch.checkNow());
            }
            assertEquals(List.of(0, 1, 0, 0), takes, "a dump that fails is tried once");
            assertNull(outcomes.get(outcomes.size() - 1).redacted());
        }
    }
}
