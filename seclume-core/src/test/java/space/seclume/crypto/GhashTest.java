package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/**
 * GHASH keeps its key where the caller put it. Until 20.10.2026 it copied H
 * into two {@code final long} fields - on the heap, in every heap dump, and
 * beyond the reach of any wipe - while its own documentation said the key
 * stayed with the caller.
 */
class GhashTest {

    private static final HexFormat HEX = HexFormat.of();

    /** SP 800-38D test case 2: H for the zero key, one zero block, no AAD. */
    @Test
    void theStandardVector() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment h = segment(arena, "66e94bd4ef8a2c3b884cfa59ca342b2e");
            MemorySegment block = segment(arena, "0388dace60b6a392f328c2b971b2fe78");
            MemorySegment out = arena.allocate(16);
            try (Ghash ghash = new Ghash(h, 0)) {
                ghash.update(block, 0, 16);
                ghash.updateLengths(0, 16);
                ghash.doFinal(out, 0);
            }
            assertEquals("f38cbb1ad69223dcc3457ae5b6b0f885",
                    HEX.formatHex(out.toArray(ValueLayout.JAVA_BYTE)));
        }
    }

    /** Wiping the caller's key reaches the hash: there is no copy of it to miss. */
    @Test
    void theKeyIsReadWhereTheCallerKeepsItNotCopied() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment h = segment(arena, "66e94bd4ef8a2c3b884cfa59ca342b2e");
            MemorySegment block = segment(arena, "0388dace60b6a392f328c2b971b2fe78");
            MemorySegment out = arena.allocate(16);
            try (Ghash ghash = new Ghash(h, 0)) {
                h.fill((byte) 0);
                ghash.update(block, 0, 16);
                ghash.doFinal(out, 0);
            }
            // Multiplied by a zero key, any block hashes to zero.
            assertEquals("00000000000000000000000000000000",
                    HEX.formatHex(out.toArray(ValueLayout.JAVA_BYTE)));
        }
    }

    @Test
    void aClosedGhashIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment h = arena.allocate(16);
            Ghash ghash = new Ghash(h, 0);
            ghash.close();
            assertThrows(IllegalStateException.class, () -> ghash.update(h, 0));
        }
    }

    @Test
    void aKeyShorterThanSixteenBytesIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment h = arena.allocate(16);
            assertThrows(IllegalArgumentException.class, () -> new Ghash(h, 1));
        }
    }

    private static MemorySegment segment(Arena arena, String hex) {
        return arena.allocateFrom(ValueLayout.JAVA_BYTE, HEX.parseHex(hex));
    }
}
