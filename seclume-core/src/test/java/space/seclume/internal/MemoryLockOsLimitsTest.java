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
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/** Actual Linux limits in child JVMs, never a limit change to the test runner. */
@EnabledOnOs(OS.LINUX)
@Timeout(120)
class MemoryLockOsLimitsTest {

    @TempDir
    Path temporary;

    @ParameterizedTest
    @CsvSource({"zero,false,0", "zero,true,0", "overlap,false,1", "overlap,true,1",
            "contention,true,8"})
    void realOperatingSystemLimits(String mode, boolean required, int pages) throws Exception {
        long limit = pages * MemoryLock.pageSize();
        Path output = temporary.resolve(mode + "-" + required + ".log");
        String classpath = System.getProperty("surefire.test.class.path",
                System.getProperty("java.class.path"));
        Process child = new ProcessBuilder(prlimit(), "--memlock=" + limit + ":" + limit,
                "--", Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED", "-Dseclume.mlock=true",
                "-Dseclume.mlock.required=" + required, "-cp", classpath,
                MemoryLockOsLimitsTest.class.getName(), mode, Long.toString(limit))
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        try {
            assertTrue(child.waitFor(90, TimeUnit.SECONDS), "memlock child timed out");
            String report = Files.readString(output);
            assertEquals(0, child.exitValue(), report);
            assertTrue(report.contains("MEMLOCK PASS " + mode), report);
            System.out.print(report);
        } finally {
            if (child.isAlive()) {
                child.destroyForcibly();
                assertTrue(child.waitFor(10, TimeUnit.SECONDS), "memlock child did not exit");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        assertTrue(Platform.isLinux());
        long limit = Long.parseLong(args[1]);
        String limits = Files.readAllLines(Path.of("/proc/self/limits")).stream()
                .filter(line -> line.startsWith("Max locked memory")).findFirst().orElseThrow();
        String[] columns = limits.trim().split("\\s+");
        assertEquals(limit, Long.parseLong(columns[3]));
        assertEquals(limit, Long.parseLong(columns[4]));
        long capabilities = Long.parseUnsignedLong(status("CapEff:"), 16);
        assertEquals(0, capabilities & (1L << 14), "CAP_IPC_LOCK would bypass the limit");
        assertTrue(MemoryLock.canExcludeFromDumps(), "Linux dump exclusion unavailable");
        switch (args[0]) {
            case "zero" -> zeroLimit();
            case "overlap" -> overlapAtLimit();
            case "contention" -> {
                contend(1, 1);
                contend(8, 1);
                contend(32, 1);
                contend(32, 8);
            }
            default -> throw new IllegalArgumentException(args[0]);
        }
        assertEquals(0, MemoryLock.pagesInUse(), "page references leaked");
        assertEquals(0, SecretScope.open(), "scopes leaked");
        assertEquals(0, lockedBytes(), "kernel locks leaked");
        System.out.println("MEMLOCK PASS " + args[0] + " limit=" + limit);
    }

    private static void zeroLimit() throws Exception {
        boolean required = Boolean.getBoolean("seclume.mlock.required");
        long page = MemoryLock.pageSize();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment segment = arena.allocate(page, page);
            if (required) {
                for (int i = 0; i < 50; i++) {
                    assertThrows(IllegalStateException.class, () -> MemoryLock.lock(segment));
                    assertEquals(0, MemoryLock.pagesInUse());
                    assertFalse(flags(segment.address()).contains("dd"));
                    assertThrows(IllegalStateException.class, () -> SecretScope.allocate(64));
                    assertEquals(0, SecretScope.open());
                }
                SecretProvider untouched = new SecretProvider() {
                    @Override
                    public int maxSecretLength() {
                        return 64;
                    }

                    @Override
                    public int writeSecret(MemorySegment target) {
                        throw new AssertionError("provider called before memory was secured");
                    }
                };
                assertThrows(IllegalStateException.class, () -> SecretScope.fromProvider(untouched));
            } else {
                for (int i = 0; i < 50; i++) {
                    assertFalse(MemoryLock.lock(segment));
                    try {
                        assertEquals(1, MemoryLock.pagesInUse());
                        assertTrue(flags(segment.address()).contains("dd"));
                        assertEquals(0, lockedBytes());
                    } finally {
                        MemoryLock.unlock(segment);
                    }
                    assertEquals(0, MemoryLock.pagesInUse());
                    assertFalse(flags(segment.address()).contains("dd"));
                    try (SecretScope scope = SecretScope.allocate(64)) {
                        assertFalse(scope.isLocked());
                    }
                    assertEquals(0, SecretScope.open());
                }
            }
        }
    }

    private static void overlapAtLimit() throws Exception {
        long page = MemoryLock.pageSize();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment whole = arena.allocate(2 * page, page);
            MemorySegment keeper = whole.asSlice(0, 32);
            MemorySegment second = whole.asSlice(page, 32);
            assertTrue(MemoryLock.lock(keeper));
            try {
                for (int i = 0; i < 50; i++) {
                    if (Boolean.getBoolean("seclume.mlock.required")) {
                        assertThrows(IllegalStateException.class, () -> MemoryLock.lock(whole));
                    } else {
                        boolean pinned = MemoryLock.lock(whole);
                        try {
                            assertFalse(pinned, "two pages fit a one-page quota");
                        } finally {
                            MemoryLock.unlock(whole);
                        }
                    }
                    assertEquals(1, MemoryLock.pagesInUse());
                    assertEquals(page, lockedBytes());
                    assertProtected(keeper);
                    assertFalse(flags(second.address()).contains("dd"));
                    assertFalse(flags(second.address()).contains("lo"));
                    // Locking an already pinned page must not consume the quota twice.
                    assertTrue(MemoryLock.lock(keeper));
                    MemoryLock.unlock(keeper);
                }
            } finally {
                MemoryLock.unlock(keeper);
            }
            assertEquals(0, lockedBytes());
            assertFalse(flags(keeper.address()).contains("dd"));
            assertTrue(MemoryLock.lock(second), "released quota was not reusable");
            try {
                assertProtected(second);
                assertEquals(page, lockedBytes());
            } finally {
                MemoryLock.unlock(second);
            }
        }
    }

    private static void contend(int threads, int pageCount) throws Exception {
        int iterations = 1000;
        long page = MemoryLock.pageSize();
        long[] samples = new long[threads * iterations];
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        try (Arena arena = Arena.ofShared()) {
            MemorySegment memory = arena.allocate(pageCount * page, page);
            for (int p = 0; p < pageCount; p++) {
                assertTrue(MemoryLock.lock(memory.asSlice(p * page, 32)));
            }
            try {
                for (int t = 0; t < threads; t++) {
                    int worker = t;
                    MemorySegment mine = memory.asSlice((t % pageCount) * page + 64 + 32L * t, 16);
                    Thread.ofPlatform().start(() -> {
                        try {
                            assertTrue(start.await(10, TimeUnit.SECONDS));
                            for (int i = 0; i < iterations; i++) {
                                long before = System.nanoTime();
                                assertTrue(MemoryLock.lock(mine));
                                MemoryLock.unlock(mine);
                                samples[worker * iterations + i] = System.nanoTime() - before;
                            }
                        } catch (Throwable error) {
                            failure.compareAndSet(null, error);
                        } finally {
                            done.countDown();
                        }
                    });
                }
                long before = System.nanoTime();
                start.countDown();
                while (!done.await(10, TimeUnit.MILLISECONDS)) {
                    assertEquals(pageCount, MemoryLock.pagesInUse());
                    assertEquals(pageCount * page, lockedBytes());
                    assertProtected(memory);
                }
                long elapsed = System.nanoTime() - before;
                if (failure.get() != null) {
                    throw new AssertionError("memlock worker failed", failure.get());
                }
                assertEquals(pageCount, MemoryLock.pagesInUse());
                assertEquals(pageCount * page, lockedBytes());
                for (int p = 0; p < pageCount; p++) {
                    assertProtected(memory.asSlice(p * page, 32));
                }
                Arrays.sort(samples);
                System.out.printf(java.util.Locale.ROOT,
                        "MEMLOCK contention threads=%d pages=%d operations=%d ms=%.3f p50_us=%.3f p99_us=%.3f%n",
                        threads, pageCount, samples.length, elapsed / 1_000_000.0,
                        samples[samples.length / 2] / 1000.0,
                        samples[(samples.length * 99) / 100] / 1000.0);
            } finally {
                start.countDown();
                assertTrue(done.await(30, TimeUnit.SECONDS), "workers did not finish");
                for (int p = 0; p < pageCount; p++) {
                    MemoryLock.unlock(memory.asSlice(p * page, 32));
                }
            }
        }
    }

    private static void assertProtected(MemorySegment memory) throws IOException {
        List<String> flags = flags(memory.address());
        assertTrue(flags.contains("dd"), "live page became dumpable");
        assertTrue(flags.contains("lo"), "live page became unlocked");
    }

    /** By absolute path, so the child cannot come from a directory on {@code PATH}. */
    private static String prlimit() {
        for (String executable : List.of("/usr/bin/prlimit", "/bin/prlimit")) {
            if (Files.isExecutable(Path.of(executable))) {
                return executable;
            }
        }
        throw new AssertionError("prlimit not found in /usr/bin or /bin");
    }

    private static long lockedBytes() throws IOException {
        String kilobytes = status("VmLck:").split("\\s+")[0];
        try {
            return Long.parseLong(kilobytes) * 1024;
        } catch (NumberFormatException unexpected) {
            throw new AssertionError("VmLck is not a number: " + kilobytes, unexpected);
        }
    }

    private static String status(String key) throws IOException {
        return Files.readAllLines(Path.of("/proc/self/status")).stream()
                .filter(line -> line.startsWith(key)).findFirst().orElseThrow()
                .substring(key.length()).trim();
    }

    private static List<String> flags(long address) throws IOException {
        boolean inside = false;
        for (String line : Files.readAllLines(Path.of("/proc/self/smaps"))) {
            int dash = line.indexOf('-');
            int space = line.indexOf(' ');
            if (dash > 0 && space > dash && line.substring(0, dash).matches("[0-9a-f]+")) {
                long begin = Long.parseUnsignedLong(line.substring(0, dash), 16);
                long end = Long.parseUnsignedLong(line.substring(dash + 1, space), 16);
                inside = Long.compareUnsigned(address, begin) >= 0
                        && Long.compareUnsigned(address, end) < 0;
            } else if (inside && line.startsWith("VmFlags:")) {
                return List.of(line.substring(8).trim().split("\\s+"));
            }
        }
        throw new AssertionError("page mapping missing");
    }
}
