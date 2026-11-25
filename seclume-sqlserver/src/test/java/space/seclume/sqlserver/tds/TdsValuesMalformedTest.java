package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * Lengths off a hostile wire end as {@link WireBuffer.Truncated} - which the
 * session turns into a SQLException - and never as an exception no caller can
 * act on.
 *
 * <p>The first case is the one the nightly fuzz run found on 27.09.2026: a
 * sql_variant of two bytes whose property count is 100, which made the value's
 * length -100 and reached {@code new byte[-100]}.
 */
class TdsValuesMalformedTest {

    private static WireBuffer buffer(int... bytes) {
        WireBuffer in = new WireBuffer(bytes.length + 16);
        for (int b : bytes) {
            in.putByte((byte) b);
        }
        in.position(0);
        in.limit(bytes.length);
        return in;
    }

    @Test
    void aVariantWhosePropertiesOutrunItIsRefused() {
        // The legacy VARCHAR: single-byte text without a collation of its own, so
        // nothing is read between the property count and the value - as in the
        // fuzz finding. With BIGVARCHAR the collation read failed first, for the
        // right type and the wrong reason.
        try (WireBuffer in = buffer(TdsTypes.VARCHAR, 100)) {
            assertThrows(WireBuffer.Truncated.class,
                    () -> TdsValues.asText(in, TdsTypes.SQLVARIANT, 0, 2, 0));
        }
    }

    /**
     * MS-TDS: a sql_variant never holds another. Taken as it came, each level
     * cost two bytes and a recursion - 8016 bytes were a StackOverflowError.
     */
    @Test
    void aVariantInsideAVariantIsMalformed() {
        int[] nested = new int[8016];
        for (int i = 0; i < nested.length; i += 2) {
            nested[i] = TdsTypes.SQLVARIANT;
            nested[i + 1] = 0;
        }
        try (WireBuffer in = buffer(nested)) {
            // Refused at the first level for what it is - not 4008 levels
            // down, where the bytes ran out.
            WireBuffer.Truncated text = assertThrows(WireBuffer.Truncated.class,
                    () -> TdsValues.asText(in, TdsTypes.SQLVARIANT, 0, nested.length, 0));
            org.junit.jupiter.api.Assertions.assertTrue(
                    text.getMessage().contains("holds a sql_variant"), text.getMessage());
            assertThrows(WireBuffer.Truncated.class,
                    () -> TdsValues.asLong(in, TdsTypes.SQLVARIANT, 0, nested.length));
        }
    }

    @Test
    void aVariantTooShortForItsHeaderIsRefused() {
        try (WireBuffer in = buffer(TdsTypes.VARCHAR)) {
            assertThrows(WireBuffer.Truncated.class,
                    () -> TdsValues.asText(in, TdsTypes.SQLVARIANT, 0, 1, 0));
        }
    }

    @Test
    void textAndBytesLongerThanTheBufferAreRefusedBeforeAnArrayIsMade() {
        try (WireBuffer in = buffer('a', 'b', 'c')) {
            assertThrows(WireBuffer.Truncated.class,
                    () -> TdsValues.asText(in, TdsTypes.BIGVARCHAR, 0, Integer.MAX_VALUE - 8, 0));
            assertThrows(WireBuffer.Truncated.class,
                    () -> TdsValues.asText(in, TdsTypes.BIGVARCHAR, 0, -5, 0));
            assertThrows(WireBuffer.Truncated.class,
                    () -> TdsValues.asBytes(in, 0, Integer.MAX_VALUE - 8));
            assertThrows(WireBuffer.Truncated.class,
                    () -> TdsValues.asBytes(in, 0, -1));
        }
    }

    @Test
    void aWellFormedVariantStillReads() {
        // varchar in a variant: type, 7 property bytes (collation 5, max length 2), "hi"
        try (WireBuffer in = buffer(TdsTypes.BIGVARCHAR, 7, 0x09, 0x04, 0xd0, 0x00, 0x34,
                0x00, 0x1f, 'h', 'i')) {
            assertEquals("hi", TdsValues.asText(in, TdsTypes.SQLVARIANT, 0, 11, 0));
        }
    }
}
