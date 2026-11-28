package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.secret.SecretScope;

/**
 * Secret pages: what {@code memfd_secret} promises, checked where the kernel
 * has it - a block is not readable through {@code /proc/self/mem}, while the
 * memory beside it is - and the pool around it: blocks wiped and taken back,
 * chunks added and given back to the kernel before a checkpoint. Where the
 * kernel has none, that is said and the secret goes where it went before.
 * Isolated: the pool is the process's, and the tests count its blocks.
 */
@Isolated
class SecretMemoryTest {

    private static final byte[] PATTERN = "secret-pages-pattern-42".getBytes(
            java.nio.charset.StandardCharsets.US_ASCII);

    @Test
    void theSettingIsOnOffOrRequired() {
        assertEquals(SecretMemory.Mode.ON, SecretMemory.mode(null));
        assertEquals(SecretMemory.Mode.ON, SecretMemory.mode(""));
        assertEquals(SecretMemory.Mode.ON, SecretMemory.mode("TRUE"));
        assertEquals(SecretMemory.Mode.OFF, SecretMemory.mode("false"));
        assertEquals(SecretMemory.Mode.REQUIRED, SecretMemory.mode("required"));
        IllegalStateException wrong = assertThrows(IllegalStateException.class,
                () -> SecretMemory.mode("sometimes"));
        assertTrue(wrong.getMessage().contains("true, false or required"), wrong.getMessage());
    }

    /** Where the kernel has none, that is said, and nothing is handed out. */
    @Test
    void withoutSecretPagesTheReasonIsSaid() {
        Assumptions.assumeFalse(SecretMemory.inUse(), "this kernel has secret pages");
        assertNotNull(SecretMemory.unavailableBecause());
        try (Arena arena = Arena.ofConfined()) {
            assertNull(SecretMemory.allocate(64, arena));
        }
        if (!Platform.isLinux()) {
            assertTrue(SecretMemory.unavailableBecause().contains("Linux"),
                    SecretMemory.unavailableBecause());
        }
    }

    /**
     * The point of it: a secret block cannot be read through /proc/self/mem -
     * nor, then, by another process or root through it - while a page of
     * ordinary native memory beside it can.
     */
    @Test
    void aSecretBlockIsNotReadableThroughProcMem() throws Exception {
        Assumptions.assumeTrue(SecretMemory.inUse(), "no secret pages here: "
                + SecretMemory.unavailableBecause());
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = SecretMemory.allocate(PATTERN.length, arena);
            MemorySegment.copy(PATTERN, 0, secret, ValueLayout.JAVA_BYTE, 0, PATTERN.length);
            MemorySegment ordinary = arena.allocate(PATTERN.length);
            MemorySegment.copy(PATTERN, 0, ordinary, ValueLayout.JAVA_BYTE, 0, PATTERN.length);
            assertArrayEquals(PATTERN, read(ordinary.address(), PATTERN.length),
                    "the control: ordinary memory is readable through /proc/self/mem");
            byte[] seen = null;
            try {
                seen = read(secret.address(), PATTERN.length);
            } catch (IOException refused) {
                // what memfd_secret promises
            }
            assertTrue(seen == null || !java.util.Arrays.equals(PATTERN, seen),
                    "a secret block was read through /proc/self/mem");
            assertArrayEquals(PATTERN, secret.asSlice(0, PATTERN.length)
                    .toArray(ValueLayout.JAVA_BYTE), "the process itself reads it");
        }
    }

    private static byte[] read(long address, int length) throws IOException {
        try (RandomAccessFile memory = new RandomAccessFile("/proc/self/mem", "r")) {
            memory.seek(address);
            byte[] out = new byte[length];
            memory.readFully(out);
            return out;
        }
    }

    /**
     * Blocks are wiped when given back, the pool grows by chunks and takes a
     * secret larger than a chunk, and before a checkpoint the chunks nothing
     * is lent from go back to the kernel.
     */
    @Test
    void blocksAreWipedTakenBackAndIdleChunksReleased() {
        Assumptions.assumeTrue(SecretMemory.inUse(), "no secret pages here: "
                + SecretMemory.unavailableBecause());
        SecretMemory.releaseIdle();
        int lentBefore = SecretMemory.lent();
        long address;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment block = SecretMemory.allocate(PATTERN.length, arena);
            address = block.address();
            MemorySegment.copy(PATTERN, 0, block, ValueLayout.JAVA_BYTE, 0, PATTERN.length);
            assertEquals(lentBefore + 1, SecretMemory.lent());
        }
        assertEquals(lentBefore, SecretMemory.lent(), "the block was not taken back");
        // Still mapped, now free: it was wiped on the way back.
        byte[] after = MemorySegment.ofAddress(address).reinterpret(PATTERN.length)
                .toArray(ValueLayout.JAVA_BYTE);
        assertArrayEquals(new byte[PATTERN.length], after, "a block went back with its secret");

        List<Arena> arenas = new ArrayList<>();
        try {
            // More than one chunk's worth of 4 KiB blocks, and one larger than a chunk.
            for (int i = 0; i < 20; i++) {
                Arena arena = Arena.ofConfined();
                arenas.add(arena);
                assertNotNull(SecretMemory.allocate(4096, arena));
            }
            Arena large = Arena.ofConfined();
            arenas.add(large);
            MemorySegment big = SecretMemory.allocate(SecretMemory.CHUNK + 1, large);
            assertEquals(SecretMemory.CHUNK + 1, big.byteSize());
            big.set(ValueLayout.JAVA_BYTE, SecretMemory.CHUNK, (byte) 7);
            assertTrue(SecretMemory.chunks() >= 2, "twenty 4 KiB blocks fit no single chunk");
        } finally {
            arenas.forEach(Arena::close);
        }
        assertEquals(lentBefore, SecretMemory.lent());
        if (lentBefore == 0) {
            assertTrue(secretMappings() > 0, "no secret mapping in /proc/self/maps");
            assertTrue(SecretMemory.releaseIdle() >= 2);
            assertEquals(0, SecretMemory.chunks(), "an idle chunk stayed mapped");
            assertEquals(0, secretMappings(), "a chunk released stayed in /proc/self/maps");
        }
    }

    /** The secret mappings the kernel lists for this process. */
    private static long secretMappings() {
        try {
            return java.nio.file.Files.readAllLines(java.nio.file.Path.of("/proc/self/maps"))
                    .stream().filter(line -> line.contains("secretmem")).count();
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /**
     * The pool itself, on ordinary pages where the kernel has no secret ones:
     * blocks of every size a secret has never overlap, keep what is written
     * to them, come back wiped, the pool grows chunk by chunk and splits a
     * new chunk down to the size asked for (a null block in CI before), takes
     * a secret larger than a chunk, and gives idle chunks back.
     */
    @Test
    void thePoolHandsOutBlocksThatNeverOverlap() {
        SecretMemory.useForTests(length -> Arena.global().allocate(length, 4096).address());
        try {
            List<Arena> arenas = new ArrayList<>();
            List<MemorySegment> blocks = new ArrayList<>();
            int[] sizes = {1, 15, 16, 17, 31, 32, 100, 255, 256, 1000, 4096, 5000, 30_000,
                (int) SecretMemory.CHUNK, (int) SecretMemory.CHUNK + 1, 3};
            for (int round = 0; round < 3; round++) {
                for (int size : sizes) {
                    Arena arena = Arena.ofConfined();
                    arenas.add(arena);
                    MemorySegment block = SecretMemory.allocate(size, arena);
                    assertNotNull(block, "size " + size);
                    assertEquals(size, block.byteSize());
                    assertArrayEquals(new byte[size], block.toArray(ValueLayout.JAVA_BYTE),
                            "a block came out not wiped");
                    block.fill((byte) (blocks.size() + 1));
                    blocks.add(block);
                }
            }
            for (int i = 0; i < blocks.size(); i++) {
                MemorySegment block = blocks.get(i);
                for (int j = i + 1; j < blocks.size(); j++) {
                    MemorySegment other = blocks.get(j);
                    assertTrue(block.address() + block.byteSize() <= other.address()
                            || other.address() + other.byteSize() <= block.address(),
                            "two blocks overlap");
                }
                byte expected = (byte) (i + 1);
                for (long at = 0; at < block.byteSize(); at++) {
                    assertEquals(expected, block.get(ValueLayout.JAVA_BYTE, at), "block " + i);
                }
            }
            assertEquals(blocks.size(), SecretMemory.lent());
            assertTrue(SecretMemory.chunks() >= 2);
            arenas.forEach(Arena::close);
            assertEquals(0, SecretMemory.lent(), "a block was not taken back");
            assertTrue(SecretMemory.releaseIdle() >= 2);
            assertEquals(0, SecretMemory.chunks());
            // And again after the release: a fresh chunk, split down once more.
            try (Arena arena = Arena.ofConfined()) {
                assertNotNull(SecretMemory.allocate(24, arena));
            }
        } finally {
            SecretMemory.useForTests(null);
        }
    }

    /**
     * Pages for the pool from one stretch of ordinary memory, one after the
     * other - so that two chunks are neighbours, as mappings of the kernel's
     * can be, and a block at a chunk's very end is told from the next one's
     * first. Each request noted; fails while {@code full}.
     */
    private static final class Pages implements java.util.function.LongUnaryOperator {
        final List<Long> lengths = new ArrayList<>();
        final List<Long> bases = new ArrayList<>();
        private final MemorySegment stretch = Arena.global().allocate(SecretMemory.CHUNK * 96, 4096);
        private long used;
        volatile boolean full;

        @Override
        public long applyAsLong(long length) {
            if (full) {
                return -12;                                   // ENOMEM: the memlock limit
            }
            lengths.add(length);
            long base = stretch.address() + used;
            used += length;
            bases.add(base);
            return base;
        }
    }

    /**
     * Small blocks come out of one chunk in a fixed order - the lower half of
     * every split first - and as many as fit in a chunk need no second one.
     */
    @Test
    void blocksComeOutOfAChunkInOrderAndFillIt() {
        Pages pages = new Pages();
        SecretMemory.useForTests(pages);
        List<Arena> arenas = new ArrayList<>();
        try {
            assertEquals(0, SecretMemory.chunks(), "the pool did not start empty");
            assertEquals(0, SecretMemory.lent());
            long[] offsets = new long[5];
            int[] sizes = {16, 16, 16, 16, 32};
            for (int i = 0; i < sizes.length; i++) {
                Arena arena = Arena.ofConfined();
                arenas.add(arena);
                offsets[i] = SecretMemory.allocate(sizes[i], arena).address() - pages.bases.get(0);
            }
            assertArrayEquals(new long[] {0, 16, 32, 48, 64}, offsets, "blocks out of order");
            assertEquals(1, SecretMemory.chunks());
            assertEquals(List.of(SecretMemory.CHUNK), pages.lengths);
            assertEquals(5, SecretMemory.lent());
            arenas.forEach(Arena::close);
            arenas.clear();
            assertEquals(0, SecretMemory.lent());
            assertEquals(1, SecretMemory.releaseIdle());
            assertEquals(0, SecretMemory.chunks());

            // Sixty-four of 1 KiB fill one chunk exactly; the sixty-fifth needs a second.
            for (int i = 0; i < 64; i++) {
                Arena arena = Arena.ofConfined();
                arenas.add(arena);
                SecretMemory.allocate(1024, arena);
            }
            assertEquals(1, SecretMemory.chunks(), "64 KiB of 1 KiB blocks took more than a chunk");
            Arena one = Arena.ofConfined();
            arenas.add(one);
            SecretMemory.allocate(1024, one);
            assertEquals(2, SecretMemory.chunks());
            // Every block of the first chunk back, one of the second still lent:
            // only the first is released.
            for (int i = 0; i < 64; i++) {
                arenas.get(i).close();
            }
            assertEquals(1, SecretMemory.lent());
            assertEquals(1, SecretMemory.releaseIdle(), "a chunk in use was released");
            assertEquals(1, SecretMemory.chunks());
            one.close();
            assertEquals(1, SecretMemory.releaseIdle());
        } finally {
            for (Arena arena : arenas) {
                if (arena.scope().isAlive()) {
                    arena.close();
                }
            }
            SecretMemory.useForTests(null);
        }
    }

    /**
     * A block given back is used again, and comes out wiped even when
     * something wrote into it meanwhile; a secret larger than a chunk gets a
     * mapping of whole chunks of its own, given back on close.
     */
    @Test
    void aBlockIsReusedWipedAndALargeSecretMapsWholeChunks() {
        Pages pages = new Pages();
        SecretMemory.useForTests(pages);
        try {
            long address;
            try (Arena arena = Arena.ofConfined()) {
                address = SecretMemory.allocate(100, arena).address();
            }
            MemorySegment.ofAddress(address).reinterpret(128).fill((byte) 0x5a);
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment again = SecretMemory.allocate(100, arena);
                assertEquals(address, again.address(), "the free block was not used again");
                assertArrayEquals(new byte[100], again.toArray(ValueLayout.JAVA_BYTE),
                        "a block was handed out unwiped");
            }
            int chunks = SecretMemory.chunks();
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment large = SecretMemory.allocate(SecretMemory.CHUNK * 2 + 1, arena);
                assertEquals(SecretMemory.CHUNK * 2 + 1, large.byteSize());
                assertEquals(SecretMemory.CHUNK * 3, pages.lengths.get(pages.lengths.size() - 1),
                        "not rounded up to whole chunks");
                assertEquals(chunks, SecretMemory.chunks(), "a large secret counted as a chunk");
                assertEquals(1, SecretMemory.lent());
            }
            assertEquals(0, SecretMemory.lent(), "the large mapping was not given back");
            try (Arena arena = Arena.ofConfined()) {
                int before = SecretMemory.chunks();
                SecretMemory.allocate(SecretMemory.CHUNK, arena);
                assertEquals(before + 1, SecretMemory.chunks(),
                        "a secret of exactly a chunk is no large one: it takes a chunk");
            }
            try (Arena arena = Arena.ofConfined()) {
                SecretMemory.allocate(SecretMemory.CHUNK * 2, arena);
                assertEquals(SecretMemory.CHUNK * 2, pages.lengths.get(pages.lengths.size() - 1),
                        "two chunks exactly were rounded up to three");
            }
        } finally {
            SecretMemory.useForTests(null);
        }
    }

    /**
     * Two chunks side by side: releasing the first keeps the free block at the
     * very start of the second - the next one handed out - and takes nothing
     * of the second's.
     */
    @Test
    void releasingAChunkKeepsItsNeighboursFreeBlocks() {
        Pages pages = new Pages();
        SecretMemory.useForTests(pages);
        List<Arena> first = new ArrayList<>();
        try {
            for (int i = 0; i < 64; i++) {
                Arena arena = Arena.ofConfined();
                first.add(arena);
                SecretMemory.allocate(1024, arena);
            }
            Arena start = Arena.ofConfined();
            long atStart = SecretMemory.allocate(1024, start).address();
            Arena next = Arena.ofConfined();
            SecretMemory.allocate(1024, next);
            assertEquals(2, SecretMemory.chunks());
            assertEquals(pages.bases.get(1).longValue(), atStart, "the second chunk's first block");
            assertEquals(pages.bases.get(0) + SecretMemory.CHUNK, atStart, "the chunks are not neighbours");
            start.close();                                       // free, at the second chunk's start
            first.forEach(Arena::close);
            assertEquals(1, SecretMemory.releaseIdle());
            assertEquals(1, SecretMemory.chunks());
            try (Arena again = Arena.ofConfined()) {
                assertEquals(atStart, SecretMemory.allocate(1024, again).address(),
                        "the free block at the second chunk's start was lost with the first chunk");
                assertEquals(1, SecretMemory.chunks());
            }
            next.close();
        } finally {
            SecretMemory.useForTests(null);
        }
    }

    /** No room for another chunk: the secret goes where it went before, and nothing breaks. */
    @Test
    void withoutRoomForAChunkTheSecretGoesToLockedPages() {
        Assumptions.assumeTrue(SecretMemory.MODE == SecretMemory.Mode.ON, "not the default here");
        Pages pages = new Pages();
        SecretMemory.useForTests(pages);
        try {
            pages.full = true;
            try (Arena arena = Arena.ofConfined()) {
                assertNull(SecretMemory.allocate(64, arena), "no chunk, yet a block");
                assertNull(SecretMemory.allocate(SecretMemory.CHUNK + 1, arena));
            }
            assertEquals(0, SecretMemory.lent());
        } finally {
            SecretMemory.useForTests(null);
        }
    }

    /** What is said for each errno. */
    @Test
    void eachRefusalIsNamed() {
        assertTrue(SecretMemory.reason(38).contains("ENOSYS"));
        assertTrue(SecretMemory.reason(12).contains("memlock"));
        assertTrue(SecretMemory.reason(11).contains("memlock"));
        assertTrue(SecretMemory.reason(1).contains("EPERM"));
        assertTrue(SecretMemory.reason(100_000).contains("could not be called"));
        assertTrue(SecretMemory.reason(5).contains("errno 5"));
    }

    /**
     * Where the kernel offers them by default - Linux 6.5 on - they are in
     * use: a test that only skips where they are not would not notice them
     * switched off by mistake.
     */
    @Test
    void onLinuxSixFiveTheyAreInUse() {
        Assumptions.assumeTrue(Platform.isLinux(), "Linux only");
        String[] version = System.getProperty("os.version").split("[.-]");
        int major = Integer.parseInt(version[0]);
        int minor = Integer.parseInt(version[1]);
        Assumptions.assumeTrue(major > 6 || (major == 6 && minor >= 5), "before 6.5 a boot option");
        Assumptions.assumeTrue(SecretMemory.MODE != SecretMemory.Mode.OFF, "opted out");
        assertTrue(SecretMemory.inUse(), "Linux " + System.getProperty("os.version")
                + " has secret pages, and they are not used: " + SecretMemory.unavailableBecause());
        assertNull(SecretMemory.unavailableBecause());
    }

    /** Where they are in use, a secret scope's bytes lie in a secret mapping of this process. */
    @Test
    void aSecretScopeLivesInASecretMappingWhereTheyAreInUse() throws IOException {
        Assumptions.assumeTrue(SecretMemory.inUse(), "no secret pages here: "
                + SecretMemory.unavailableBecause());
        try (SecretScope scope = SecretScope.allocate(64)) {
            long address = scope.segment().address();
            boolean inside = false;
            for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of("/proc/self/maps"))) {
                if (!line.contains("secretmem")) {
                    continue;
                }
                String[] range = line.substring(0, line.indexOf(' ')).split("-");
                long from = Long.parseUnsignedLong(range[0], 16);
                long to = Long.parseUnsignedLong(range[1], 16);
                inside |= address >= from && address < to;
            }
            assertTrue(inside, "a secret scope is not in a secret mapping");
        }
    }

    /** A secret scope uses them where they are, and works the same where they are not. */
    @Test
    void aSecretScopeWorksEitherWay() {
        try (SecretScope scope = SecretScope.allocate(PATTERN.length)) {
            MemorySegment.copy(PATTERN, 0, scope.segment(), ValueLayout.JAVA_BYTE, 0,
                    PATTERN.length);
            scope.length(PATTERN.length);
            assertArrayEquals(PATTERN, scope.secret().toArray(ValueLayout.JAVA_BYTE));
        }
        try (Arena arena = Arena.ofConfined(); SecretScope scope = SecretScope.in(arena, 32)) {
            assertEquals(32, scope.segment().byteSize());
        }
    }

    /**
     * -Dseclume.dumpable=false, in a JVM of its own: on Linux the process is
     * not dumpable once it holds a secret; elsewhere the first secret is
     * refused rather than made in a process that is not what was asked for.
     */
    @Test
    void notDumpableWhenAskedOrNoSecret() throws Exception {
        Process child = new ProcessBuilder(
                java.nio.file.Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED", "-Dseclume.dumpable=false",
                "-cp", System.getProperty("java.class.path"), DumpableProbe.class.getName())
                .redirectErrorStream(true).start();
        String out = new String(child.getInputStream().readAllBytes(),
                java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(child.waitFor(60, java.util.concurrent.TimeUnit.SECONDS));
        if (Platform.isLinux()) {
            assertTrue(out.contains("not dumpable: true"), out);
        } else {
            assertTrue(out.contains("refused: ") && out.contains("seclume.dumpable=false"), out);
        }
        assertFalse(ProcessHardening.ASKED, "this JVM was not asked");
        assertFalse(ProcessHardening.notDumpableNow(), "this JVM was made not dumpable");
    }

    /** The child of {@link #notDumpableWhenAskedOrNoSecret()}. */
    public static final class DumpableProbe {
        public static void main(String[] args) {
            try (SecretScope scope = SecretScope.allocate(16)) {
                System.out.println("not dumpable: " + ProcessHardening.notDumpableNow()
                        + " " + scope.segment().byteSize());
            } catch (IllegalStateException refused) {
                System.out.println("refused: " + refused.getMessage());
            }
        }
    }
}
