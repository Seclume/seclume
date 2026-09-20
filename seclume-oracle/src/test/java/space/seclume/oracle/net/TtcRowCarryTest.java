package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * A value the server did not send again, because it was the same as in the
 * row before - and the row before was in the previous fetch.
 *
 * <p>Oracle leaves a repeated value out of the row and marks it in a bit
 * vector, and it counts "the row before" across the boundary of a block: the
 * first row of the second fetch may refer back to the last row of the first.
 * That block has been read over by then, so the row has to have kept the
 * value.
 *
 * <p>It was found against a live server, and it is not a corner case: a
 * metadata query over a schema of a hundred and some columns produced one
 * empty table name, and Hibernate then refused to start with "missing column
 * [holder] in table [zl_ticket]" for a column that was there. Everything
 * inside one block was right, which is why it took a large schema to see it
 * at all.
 */
class TtcRowCarryTest {

    private static final List<OracleColumn> COLUMNS = List.of(
            new OracleColumn("TABLE_NAME", OracleColumn.TYPE_VARCHAR, 0, 0, 128, 128, 1, true),
            new OracleColumn("COLUMN_NAME", OracleColumn.TYPE_VARCHAR, 0, 0, 128, 128, 1, true));

    /** A row of two text values, each a length byte and its bytes. */
    private static void putRow(WireBuffer out, String... values) {
        for (String value : values) {
            out.putByte((byte) value.length());
            for (int i = 0; i < value.length(); i++) {
                out.putByte((byte) value.charAt(i));
            }
        }
    }

    @Test
    void keepsAValueThatTheNextBlockDoesNotSendAgain() {
        try (WireBuffer first = new WireBuffer(64);
                WireBuffer second = new WireBuffer(64)) {
            putRow(first, "ZL_TICKET", "SEAT_NO");
            putRow(first, "ZL_TICKET", "EVENT_NAME");

            TtcRow row = new TtcRow(first, COLUMNS);
            int p = row.read(0, null);
            assertEquals("ZL_TICKET", row.text(0));
            row.read(p, null);
            assertEquals("EVENT_NAME", row.text(1));

            // End of the block: what may still be referred to goes to safety.
            row.carryOver();
            // And the buffer is used again, as the channel would use it.
            first.clear();
            for (int i = 0; i < 32; i++) {
                first.putByte((byte) '#');
            }

            // The next block: only the second column is in the row, the bit
            // vector says the first is unchanged.
            putRow(second, "HOLDER");
            row.rebind(second);
            row.read(0, new byte[] { 0b0000_0010 });

            assertEquals("ZL_TICKET", row.text(0), "the value from the block before");
            assertEquals("HOLDER", row.text(1));
            row.release();
        }
    }

    /** Two blocks in a row must not lose it either. */
    @Test
    void keepsItOverSeveralBlocks() {
        try (WireBuffer first = new WireBuffer(64);
                WireBuffer second = new WireBuffer(64);
                WireBuffer third = new WireBuffer(64)) {
            putRow(first, "ZL_TICKET", "SEAT_NO");
            TtcRow row = new TtcRow(first, COLUMNS);
            row.read(0, null);
            row.carryOver();

            putRow(second, "EVENT_NAME");
            row.rebind(second);
            row.read(0, new byte[] { 0b0000_0010 });
            assertEquals("ZL_TICKET", row.text(0));
            row.carryOver();

            putRow(third, "HOLDER");
            row.rebind(third);
            row.read(0, new byte[] { 0b0000_0010 });
            assertEquals("ZL_TICKET", row.text(0), "still, two blocks later");
            assertEquals("HOLDER", row.text(1));
            row.release();
        }
    }
}
