package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;

/**
 * The iteration count of a SCRAM server-first message, as a number: one to
 * eight digits within 1 to 10 000 000, and a count of eleven digits that an
 * int would have wrapped into a plausible one refused instead.
 */
class ScramIterationTest {

    private static final String SALT = "YSBzYWx0IG9mIHNpeHRlZW4=";

    private static MemorySegment ascii(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    /** serverFirst with the client's own nonce and {@code count} as the iterations. */
    private static Scram withCount(Arena arena, String count) {
        Scram scram = new Scram(HashAlgorithm.SHA_256);
        MemorySegment out = arena.allocate(256);
        int length = scram.clientFirst(out, "app");
        String first = new String(out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.US_ASCII);
        String nonce = first.substring(first.indexOf(",r=") + 3);
        String serverFirst = "r=" + nonce + "srv,s=" + SALT + ",i=" + count;
        try {
            scram.serverFirst(ascii(arena, serverFirst), 0, serverFirst.length());
            return scram;
        } catch (RuntimeException e) {
            scram.close();
            throw e;
        }
    }

    @Test
    void aCountOfOneToEightDigitsInRangeIsTaken() {
        for (String[] count : new String[][] {{"1", "1"}, {"4096", "4096"}, {"00004096", "4096"},
                {"10000000", "10000000"}}) {
            try (Arena arena = Arena.ofConfined(); Scram scram = withCount(arena, count[0])) {
                assertEquals(Integer.parseInt(count[1]), scram.iterations(), count[0]);
            }
        }
    }

    @Test
    void aCountThatAnIntWouldWrapIsRefused() {
        // 2^32 + 4096: as an int, 4096.
        for (String count : new String[] {"4294971392", "99999999999", "123456789"}) {
            try (Arena arena = Arena.ofConfined()) {
                IllegalStateException e = assertThrows(IllegalStateException.class, () -> withCount(arena, count),
                        count);
                assertEquals("the iteration count is not a number of one to eight digits", e.getMessage());
            }
        }
    }

    @Test
    void anEmptyZeroOrTooLargeCountIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            assertEquals("the iteration count is not a number of one to eight digits",
                    assertThrows(IllegalStateException.class, () -> withCount(arena, "")).getMessage());
            assertEquals("implausible iteration count 0",
                    assertThrows(IllegalStateException.class, () -> withCount(arena, "0")).getMessage());
            assertEquals("implausible iteration count 10000001",
                    assertThrows(IllegalStateException.class, () -> withCount(arena, "10000001")).getMessage());
            assertEquals("the iteration count is not a number",
                    assertThrows(IllegalStateException.class, () -> withCount(arena, "40-96")).getMessage());
            assertDoesNotThrow(() -> withCount(arena, "9999999").close());
        }
    }
}
