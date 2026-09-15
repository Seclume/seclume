package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.WireBuffer;

/**
 * Integers read out of the wire format, and the edge the fast path introduced.
 *
 * <p>{@code Row#getLong} reads eight bytes in one access instead of eight,
 * because a checked access to a {@code MemorySegment} costs the same either
 * way and the cost is per access. That is worth a test of its own for one
 * reason: it can only read eight bytes when eight bytes are there. A value
 * that ends within seven bytes of the end of the buffer has to fall back to
 * reading one at a time, and that fallback is the kind of branch that is never
 * taken in a test against a real server - the receive buffer is thirty-two
 * kilobytes and a row lands in the middle of it - and always taken eventually
 * in production.
 */
class RowNumberTest {

    @ParameterizedTest
    @ValueSource(longs = {0, 1, 7, 42, 999, 1_000_000, 2_147_483_647L,
        9_223_372_036_854_775_807L, -1, -42, -9_223_372_036_854_775_808L})
    void readsIntegersFromTheMiddleOfTheBuffer(long expected) {
        // Far from either end: the whole value is read eight bytes at a time.
        assertEquals(expected, readAt(expected, 64));
    }

    @ParameterizedTest
    @ValueSource(longs = {0, 1, 7, 42, 999, 1_000_000, 2_147_483_647L,
        9_223_372_036_854_775_807L, -1, -42})
    void readsIntegersThatEndAtTheVeryEndOfTheBuffer(long expected) {
        // Placed so the value ends on the last byte of the buffer: there are
        // never eight bytes to read and every digit takes the fallback.
        assertEquals(expected, readAtEnd(expected, 0));
    }

    /**
     * And the case in between, one byte at a time across the boundary.
     *
     * <p>A value that starts more than eight bytes from the end and ends fewer
     * than eight from it uses <b>both</b> paths in one call, which is where an
     * off-by-one would live.
     */
    @Test
    void readsAValueThatStraddlesTheBoundary() {
        for (int spare = 0; spare < 9; spare++) {
            assertEquals(1234567890123L, readAtEnd(1234567890123L, spare),
                    spare + " bytes to spare after the value");
        }
    }

    /** Not a number is still not a number, on either path. */
    @ParameterizedTest
    @ValueSource(ints = {64, 0})
    void refusesWhatIsNotAnInteger(int spareAfter) {
        byte[] bytes = "12x45678".getBytes(StandardCharsets.US_ASCII);
        try (WireBuffer buffer = new WireBuffer(128)) {
            int start = buffer.capacity() - bytes.length - spareAfter;
            write(buffer, start, bytes);
            Row row = new Row(buffer, List.of(field()),
                    new int[] {start}, new int[] {bytes.length});
            assertThrows(NumberFormatException.class, () -> row.getLong(0));
        }
    }

    /** The value somewhere in the middle, with room to spare on both sides. */
    private static long readAt(long value, int start) {
        byte[] bytes = Long.toString(value).getBytes(StandardCharsets.US_ASCII);
        try (WireBuffer buffer = new WireBuffer(256)) {
            write(buffer, start, bytes);
            Row row = new Row(buffer, List.of(field()),
                    new int[] {start}, new int[] {bytes.length});
            return row.getLong(0);
        }
    }

    /**
     * The value with exactly {@code spare} bytes behind it to the end.
     *
     * <p>Against the buffer's <b>real</b> capacity, not the requested one -
     * {@code WireBuffer} rounds up, and the first version of this test placed
     * values it believed were at the end in the middle of a sixty-four byte
     * buffer. Every case took the fast path and the control run proved it: the
     * fallback could be replaced with nonsense and all of them still passed.
     */
    private static long readAtEnd(long value, int spare) {
        byte[] bytes = Long.toString(value).getBytes(StandardCharsets.US_ASCII);
        try (WireBuffer buffer = new WireBuffer(128)) {
            int start = buffer.capacity() - bytes.length - spare;
            write(buffer, start, bytes);
            Row row = new Row(buffer, List.of(field()),
                    new int[] {start}, new int[] {bytes.length});
            return row.getLong(0);
        }
    }

    private static void write(WireBuffer buffer, int start, byte[] bytes) {
        buffer.position(start);
        for (byte value : bytes) {
            buffer.putByte(value);
        }
    }

    private static PgSession.Field field() {
        return new PgSession.Field("n", 0, (short) 0, 20, (short) 8, -1, (short) 0);
    }
}
