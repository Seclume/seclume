package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * A row's cells stay inside the row. A row is a window onto the receive
 * buffer, and what follows the row there is the next packet: a cell whose
 * length runs past the row's end was read from it - the start of the next row
 * as the end of this one's last value - and an eight-byte length cut down to
 * an int came out negative, which is what NULL looks like, or small, which is
 * what a value looks like. Both formats, every length form; the bytes after
 * the row are always there in these tests, as they are on the wire.
 */
class MyRowBoundsTest {

    /** What lies behind every row here, as the next packet would. */
    private static final byte[] NEXT_PACKET = {0x05, 0x00, 0x00, 0x04, 'n', 'e', 'x', 't', '!'};

    private static MySession.Field field(int type) {
        return new MySession.Field("s", "t", "c", "c", 63, 0, type, 0, 0);
    }

    private static List<MySession.Field> fields(int count, int type) {
        List<MySession.Field> fields = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            fields.add(field(type));
        }
        return fields;
    }

    /** The row's bytes at offset 3 of a buffer, with the next packet behind it. */
    private static MyRow row(List<MySession.Field> fields, boolean binary, int... bytes) {
        WireBuffer buffer = new WireBuffer(64);
        buffer.putBytes(MemorySegment.ofArray(new byte[] {9, 9, 9}));
        byte[] row = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            row[i] = (byte) bytes[i];
        }
        buffer.putBytes(MemorySegment.ofArray(row));
        buffer.putBytes(MemorySegment.ofArray(NEXT_PACKET));
        MyRow result = new MyRow(buffer, fields, binary);
        result.start(3, row.length);
        return result;
    }

    private static void refused(String expected, List<MySession.Field> fields, boolean binary,
            int... bytes) {
        WireBuffer.Truncated refused = assertThrows(WireBuffer.Truncated.class,
                () -> row(fields, binary, bytes));
        assertTrue(refused.getMessage().contains(expected), refused.getMessage());
    }

    // ---- text rows -------------------------------------------------------

    @Test
    void textCellsThatFitAreReadInEveryLengthForm() {
        MyRow row = row(fields(3, MyTypes.VARCHAR), false,
                2, 'a', 'b', 0xfb, 0xfc, 3, 0, 'x', 'y', 'z');
        assertEquals("ab", row.getString(0));
        assertTrue(row.isNull(1));
        assertEquals("xyz", row.getString(2));
        MyRow eight = row(fields(1, MyTypes.VARCHAR), false,
                0xfe, 1, 0, 0, 0, 0, 0, 0, 0, 'q');
        assertEquals("q", eight.getString(0));
        MyRow three = row(fields(1, MyTypes.VARCHAR), false, 0xfd, 2, 0, 0, 'h', 'i');
        assertEquals("hi", three.getString(0));
        MyRow empty = row(fields(1, MyTypes.VARCHAR), false, 0);
        assertFalse(empty.isNull(0));
        assertEquals("", empty.getString(0));
    }

    @Test
    void theLastTextCellMayNotRunIntoTheNextPacket() {
        // 'ab' says four bytes: two of the row, then two of the next packet.
        refused("column 1 of 1 says 4 bytes, and the row has 2 left",
                fields(1, MyTypes.VARCHAR), false, 4, 'a', 'b');
        refused("column 2 of 2 says 9 bytes",
                fields(2, MyTypes.VARCHAR), false, 1, 'a', 9, 'b');
        refused("says 300 bytes", fields(1, MyTypes.VARCHAR), false, 0xfc, 0x2c, 0x01, 'a');
        refused("says 65536 bytes", fields(1, MyTypes.VARCHAR), false, 0xfd, 0, 0, 1, 'a');
    }

    @Test
    void anEightByteLengthIsNotCutDownToAnInt() {
        // 2^32 + 1: as an int, 1 - and the cell would have been 'x'.
        refused("says 4294967297 bytes", fields(1, MyTypes.VARCHAR), false,
                0xfe, 1, 0, 0, 0, 1, 0, 0, 0, 'x');
        // 2^64 - 1: as an int, -1 - which is NULL.
        refused("says 18446744073709551615 bytes", fields(1, MyTypes.VARCHAR), false,
                0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        // 2^31: negative as an int too, and the next column read from behind.
        refused("says 2147483648 bytes", fields(2, MyTypes.VARCHAR), false,
                0xfe, 0, 0, 0, 0x80, 0, 0, 0, 0, 1, 'y');
    }

    @Test
    void aLengthWhoseOwnBytesAreCutOffIsRefused() {
        refused("column 1 of 1 needs 9 bytes, and the row has 4 left",
                fields(1, MyTypes.VARCHAR), false, 0xfe, 1, 0, 0);
        refused("needs 3 bytes, and the row has 2 left",
                fields(1, MyTypes.VARCHAR), false, 0xfc, 1);
        refused("needs 4 bytes, and the row has 1 left",
                fields(1, MyTypes.VARCHAR), false, 0xfd);
    }

    @Test
    void aTextRowWithTooFewCellsIsStillRefused() {
        refused("the row ended after 1 of 2 columns", fields(2, MyTypes.VARCHAR), false, 1, 'a');
    }

    // ---- binary rows -----------------------------------------------------

    @Test
    void binaryCellsThatFitAreRead() {
        List<MySession.Field> fields = List.of(field(MyTypes.LONG), field(MyTypes.VARCHAR),
                field(MyTypes.DATE), field(MyTypes.TINY));
        // header 0, a NULL bitmap of one byte with column 3 (bit 5) NULL
        MyRow row = row(fields, true, 0, 0b0010_0000,
                7, 0, 0, 0,                      // LONG 7
                2, 'o', 'k',                     // VARCHAR 'ok'
                4, 0xea, 0x07, 11, 6);           // DATE 2026-11-06
        assertEquals(7, row.getLong(0));
        assertEquals("ok", row.getString(1));
        assertEquals(4, row.length(2));
        assertTrue(row.isNull(3));
    }

    @Test
    void aFixedLengthBinaryCellMayNotRunIntoTheNextPacket() {
        refused("column 1 of 1 needs 4 bytes, and the row has 2 left",
                fields(1, MyTypes.LONG), true, 0, 0, 7, 0);
        refused("column 1 of 1 needs 8 bytes, and the row has 0 left",
                fields(1, MyTypes.LONGLONG), true, 0, 0);
    }

    @Test
    void aBinaryTimeCellMayNotRunIntoTheNextPacket() {
        refused("column 1 of 1 needs 7 bytes, and the row has 2 left",
                fields(1, MyTypes.DATETIME), true, 0, 0, 7, 0xea, 0x07);
        refused("column 1 of 1 needs 1 bytes, and the row has 0 left",
                fields(1, MyTypes.TIME), true, 0, 0);
    }

    @Test
    void aBinaryStringCellIsHeldToTheRowLikeAText() {
        refused("column 1 of 1 says 5 bytes, and the row has 2 left",
                fields(1, MyTypes.VARCHAR), true, 0, 0, 5, 'a', 'b');
        refused("says 4294967297 bytes", fields(1, MyTypes.BLOB), true,
                0, 0, 0xfe, 1, 0, 0, 0, 1, 0, 0, 0, 'x');
    }

    @Test
    void aBinaryRowShorterThanItsNullBitmapIsRefused() {
        // 20 columns take a bitmap of three bytes; the row has the header and one.
        refused("a binary row of 2 bytes, where its header and NULL bitmap for 20 columns "
                + "take 4", fields(20, MyTypes.LONG), true, 0, 0);
    }
}
