package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretScope;

/**
 * A secret's pages are kept out of crash dumps - on Linux marked
 * {@code MADV_DONTDUMP}, which the kernel shows as {@code dd} among the
 * mapping's VmFlags; on Windows registered with Windows Error Reporting as
 * excluded - and running out of that is survivable.
 */
class DumpExclusionTest {

    @Test
    void aSecretsPagesAreLeftOutOfDumps() throws Exception {
        Assumptions.assumeTrue(MemoryLock.canExcludeFromDumps(), "not on this platform");
        try (SecretScope secret = SecretScope.allocate(64)) {
            assertTrue(MemoryLock.excludeFromDumps(secret.segment()),
                    "the operating system refused to leave the page out of dumps");
            if (Platform.isLinux()) {
                assertTrue(flagsOf(secret.segment().address()).contains(" dd"),
                        "the kernel does not show the page as left out of dumps");
            }
        }
    }

    @Test
    void moreSecretsThanWindowsCountsStillWork() {
        List<SecretScope> many = new ArrayList<>();
        try {
            for (int i = 0; i < 600; i++) {
                SecretScope scope = SecretScope.allocate(32);
                many.add(scope);
                scope.segment().set(java.lang.foreign.ValueLayout.JAVA_BYTE, 0, (byte) i);
            }
        } finally {
            many.forEach(SecretScope::close);
        }
    }

    /** The VmFlags line of the mapping that holds {@code address}. */
    private static String flagsOf(long address) throws Exception {
        boolean inside = false;
        for (String line : Files.readAllLines(Path.of("/proc/self/smaps"))) {
            if (Character.isLetterOrDigit(line.charAt(0)) && line.indexOf('-') > 0
                    && line.indexOf('-') < line.indexOf(' ')) {
                String[] range = line.substring(0, line.indexOf(' ')).split("-");
                long from = Long.parseUnsignedLong(range[0], 16);
                long to = Long.parseUnsignedLong(range[1], 16);
                inside = address >= from && address < to;
            } else if (inside && line.startsWith("VmFlags:")) {
                return line;
            }
        }
        return "";
    }
}
