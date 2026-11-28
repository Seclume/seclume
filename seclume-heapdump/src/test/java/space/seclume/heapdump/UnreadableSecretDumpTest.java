package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import com.sun.management.HotSpotDiagnosticMXBean;

/**
 * A real dump - this JVM's own, written by HotSpot - and a secret that cannot
 * be read when it is to be redacted: Vault down, a file gone. Nothing is
 * passed on as redacted, no partial copy is left beside it, and the original
 * is deleted where the settings say so and kept, said to hold its secrets,
 * where they do not.
 */
@Timeout(300)
class UnreadableSecretDumpTest {

    /** The application's own secrets, when the source behind them is down. */
    private static final OffHeapSecrets UNREADABLE = () -> {
        throw new IllegalStateException("the secret vault-db could not be read: connection "
                + "refused - not passed on as redacted");
    };

    private static Path dumpThisJvm(Path folder) throws Exception {
        Path dump = folder.resolve("java_pid" + ProcessHandle.current().pid() + ".hprof");
        ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class)
                .dumpHeap(dump.toString(), true);
        assertTrue(DumpFolder.complete(dump), "HotSpot wrote no finished dump");
        return dump;
    }

    private static List<Path> listing(Path folder) throws Exception {
        try (Stream<Path> files = Files.list(folder)) {
            return files.toList();
        }
    }

    @Test
    void anUnreadableSecretLeavesNoRedactedCopyAndTheDumpIsHandledAsSet(@TempDir Path folder)
            throws Exception {
        Path dump = dumpThisJvm(folder);
        DumpFolder.Settings kept = new DumpFolder.Settings(List.of(), true, Set.of(), false)
                .with(UNREADABLE);
        DumpFolder.Outcome outcome = DumpFolder.redact(dump, kept);
        assertFalse(outcome.ok(), "redacted without the secret it was to look for");
        assertNull(outcome.redacted());
        assertTrue(outcome.failure().contains("vault-db"), outcome.failure());
        assertTrue(outcome.describe().contains("still holds its secrets"), outcome.describe());
        assertEquals(List.of(dump), listing(folder), "something was left beside the dump");

        DumpFolder.Settings deleting = new DumpFolder.Settings(List.of(), true, Set.of(), true)
                .with(UNREADABLE);
        outcome = DumpFolder.redact(dump, deleting);
        assertTrue(outcome.deleted(), outcome.describe());
        assertEquals(List.of(), listing(folder), "the dump, or a part of it, is still there");
    }
}
