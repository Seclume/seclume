package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * getLong on a value no long can hold: a BIGINT UNSIGNED above
 * Long.MAX_VALUE came back negative - 2^64-1 as -1 - and a DECIMAL of twenty
 * digits wrapped modulo 2^64. Both are refused now, and the driver turns the
 * refusal into SQLState 22003.
 */
class BigintUnsignedTest {

    /** One cell of {@code bytes}, of {@code type}, binary protocol. */
    private static ValueCells cell(int type, int flags, byte[] bytes) {
        MySession.Field field = new MySession.Field("db", "t", "v", "v", 63, 20, type, flags, 0);
        return new ValueCells() {
            @Override
            public List<MySession.Field> fields() {
                return List.of(field);
            }

            @Override
            public int offset(int column) {
                return 0;
            }

            @Override
            public int length(int column) {
                return bytes.length;
            }

            @Override
            public byte byteAt(int at) {
                return bytes[at];
            }

            @Override
            public long unsignedAt(int at, int length) {
                long value = 0;
                for (int i = length - 1; i >= 0; i--) {         // little-endian
                    value = (value << 8) | (bytes[at + i] & 0xffL);
                }
                return value;
            }

            @Override
            public long decimalAt(int at, int length) {
                throw new UnsupportedOperationException();
            }

            @Override
            public String textAt(int at, int length) {
                return new String(bytes, at, length, StandardCharsets.US_ASCII);
            }
        };
    }

    private static byte[] allOnes() {
        byte[] bytes = new byte[8];
        java.util.Arrays.fill(bytes, (byte) 0xff);
        return bytes;
    }

    @Test
    void aValueAboveLongMaxIsRefused() {
        ValueCells unsigned = cell(MyTypes.LONGLONG, MyTypes.FLAG_UNSIGNED, allOnes());
        assertThrows(NumberFormatException.class, () -> BinaryValues.toLong(unsigned, 0),
                "2^64-1 came back as -1");
        // Control: the same bytes signed are -1, and that is right.
        assertEquals(-1L, BinaryValues.toLong(cell(MyTypes.LONGLONG, 0, allOnes()), 0));
    }

    @Test
    void aDecimalBeyondALongIsRefused() {
        ValueCells wide = cell(MyTypes.NEWDECIMAL, 0,
                "99999999999999999999".getBytes(StandardCharsets.US_ASCII));
        assertThrows(NumberFormatException.class, () -> BinaryValues.toLong(wide, 0));
        assertEquals(12L, BinaryValues.toLong(cell(MyTypes.NEWDECIMAL, 0,
                "12".getBytes(StandardCharsets.US_ASCII)), 0));
    }
}
