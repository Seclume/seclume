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
