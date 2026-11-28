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
            assertTrue(SecretMemory.releaseIdle() >= 2);
            assertEquals(0, SecretMemory.chunks(), "an idle chunk stayed mapped");
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
        Assumptions.assumeFalse(SecretMemory.inUse(), "the kernel's pages are tested above");
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
