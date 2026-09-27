package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.secret.SecretScope;

/**
 * MemoryLock after the audit of 27.09.2026: the real page size, native calls
 * under the same monitor as the counting, counts given back whatever mlock
 * said, and the fail-closed mode.
 *
 * <p>Isolated: two tests switch the operating system's answers off for the
 * whole JVM, and a login running beside them would see that.
 */
@Isolated
@Timeout(120)
class MemoryLockRegressionTest {

    @AfterEach
    void restore() {
        MemoryLock.failLockForTests = false;
        MemoryLock.failExcludeForTests = false;
        MemoryLock.requireForTests(false);
    }

    @Test
    void thePageSizeIsTheOperatingSystemsAndAPowerOfTwo() {
        long page = MemoryLock.pageSize();
        assertTrue(page >= 4096, "page size " + page);
        assertEquals(1, Long.bitCount(page), "page size " + page);
    }

    /**
     * mlock failing (RLIMIT_MEMLOCK) used to leave the page counted forever:
     * SecretScope skipped the unlock when the lock had not taken.
     */
    @Test
    void aScopeWhosePageCouldNotBeLockedGivesItsCountBack() {
        MemoryLock.failLockForTests = true;
        int before = MemoryLock.pagesInUse();
        for (int i = 0; i < 50; i++) {
            try (SecretScope scope = SecretScope.allocate(64)) {
                assertFalse(scope.isLocked());
            }
        }
        assertEquals(before, MemoryLock.pagesInUse(), "pages stayed counted after close");
    }

    @Test
    void failClosedRefusesAnUnlockablePageAndLeavesNothingBehind() {
        MemoryLock.requireForTests(true);
        MemoryLock.failLockForTests = true;
        int pages = MemoryLock.pagesInUse();
        long open = SecretScope.open();

        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> SecretScope.allocate(64));

        assertTrue(refused.getMessage().contains("locked into RAM"), refused.getMessage());
        assertEquals(pages, MemoryLock.pagesInUse(), "the refused segment's pages stayed counted");
        assertEquals(open, SecretScope.open(), "a refused scope counts as opened");
    }

    @Test
    void failClosedRefusesAPageThatCannotBeKeptOutOfDumps() {
        MemoryLock.requireForTests(true);
        MemoryLock.failExcludeForTests = true;
        int pages = MemoryLock.pagesInUse();

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment segment = arena.allocate(64);
            IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> MemoryLock.lock(segment));
            assertTrue(refused.getMessage().contains("crash dumps"), refused.getMessage());
        }
        assertEquals(pages, MemoryLock.pagesInUse());
    }

    @Test
    void theDefaultStaysAWarningWhenTheOperatingSystemRefuses() {
        MemoryLock.failLockForTests = true;
        MemoryLock.failExcludeForTests = true;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment segment = arena.allocate(64);
            assertFalse(MemoryLock.lock(segment), "reported as pinned although it was not");
            MemoryLock.unlock(segment);
        }
    }

    /**
     * Many secrets arriving and leaving on one page, while one stays: the
     * page must stay counted - and on Linux, excluded from dumps - for as long
     * as that one lives.
     */
    @Test
    void aLiveSecretKeepsItsPageThroughAStormOfOthers() throws Exception {
        long page = MemoryLock.pageSize();
        try (Arena arena = Arena.ofShared()) {
            MemorySegment whole = arena.allocate(page, page);
            MemorySegment keeper = whole.asSlice(0, 32);
            int before = MemoryLock.pagesInUse();
            MemoryLock.lock(keeper);
            try {
                int threads = 8;
                CyclicBarrier start = new CyclicBarrier(threads);
                AtomicReference<Throwable> failure = new AtomicReference<>();
                Thread[] workers = new Thread[threads];
                for (int t = 0; t < threads; t++) {
                    MemorySegment mine = whole.asSlice(64 + 64L * t, 32);
                    workers[t] = Thread.ofPlatform().start(() -> {
                        try {
                            start.await();
                            for (int i = 0; i < 2_000; i++) {
                                MemoryLock.lock(mine);
                                try {
                                    Thread.onSpinWait();
                                } finally {
                                    MemoryLock.unlock(mine);
                                }
                            }
                        } catch (Throwable e) {
                            failure.compareAndSet(null, e);
                        }
                    });
                }
                for (Thread worker : workers) {
                    worker.join();
                }
                if (failure.get() != null) {
                    throw new AssertionError(failure.get());
                }
                assertEquals(before + 1, MemoryLock.pagesInUse(),
                        "the live secret's page was released by the others");
                if (MemoryLock.canExcludeFromDumps() && Files.isReadable(Path.of("/proc/self/smaps"))) {
                    assertTrue(vmFlags(keeper.address()).contains("dd"),
                            "the live secret's page is back in core dumps");
                }
            } finally {
                MemoryLock.unlock(keeper);
            }
            assertEquals(before, MemoryLock.pagesInUse());
        }
    }

    @Test
    void onLinuxAnExcludedPageCarriesTheDontDumpFlag() throws IOException {
        Assumptions.assumeTrue(MemoryLock.canExcludeFromDumps()
                && Files.isReadable(Path.of("/proc/self/smaps")), "Linux only");
        long page = MemoryLock.pageSize();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment segment = arena.allocate(page, page).asSlice(0, 16);
            MemoryLock.lock(segment);
            try {
                assertTrue(vmFlags(segment.address()).contains("dd"),
                        "MADV_DONTDUMP did not take - page size " + page);
            } finally {
                MemoryLock.unlock(segment);
            }
        }
    }

    /** The VmFlags line of the mapping that contains {@code address}, from /proc/self/smaps. */
    private static String vmFlags(long address) throws IOException {
        List<String> lines = Files.readAllLines(Path.of("/proc/self/smaps"));
        boolean inside = false;
        for (String line : lines) {
            int dash = line.indexOf('-');
            int space = line.indexOf(' ');
            if (dash > 0 && space > dash && line.substring(0, dash).matches("[0-9a-f]+")) {
                long start = Long.parseUnsignedLong(line.substring(0, dash), 16);
                long end = Long.parseUnsignedLong(line.substring(dash + 1, space), 16);
                inside = Long.compareUnsigned(address, start) >= 0
                        && Long.compareUnsigned(address, end) < 0;
            } else if (inside && line.startsWith("VmFlags:")) {
                return line;
            }
        }
        return "";
    }
}
