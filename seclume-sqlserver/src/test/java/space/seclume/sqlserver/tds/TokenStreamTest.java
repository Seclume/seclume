package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The token stream against streams built by hand.
 *
 * <p>Why not against a server: a wrong length in TDS does not produce an error
 * but a shifted read, and the values after it look plausible. Against a real
 * server one sees only the end of that chain and has to guess where it began.
 * Here the bytes going in are known, so a wrong result names its own cause.
 *
 * <p>The framing was checked against a real SQL Server 2022 in an earlier
 * session - PRELOGIN, TLS inside TDS, LOGIN7. What is tested here is the layer
 * above it, which needs no server.
 */
class TokenStreamTest {

    /** Collects the rows, copied out - the row itself is only a window. */
    private record Cell(String text, long number, boolean isNull) {
    }

    private static List<List<Cell>> readAll(Tokens tokens, TokenStream stream) throws Exception {
        List<List<Cell>> rows = new ArrayList<>();
        try (WireBuffer in = tokens.buffer()) {
            stream.read(in, 0, tokens.length(), row -> {
                List<Cell> cells = new ArrayList<>();
                for (int i = 0; i < row.columnCount(); i++) {
                    // Numbers only where a number is in it - on anything else
                    // the reader falls back to parsing the text, and that is a
                    // question of its own that does not belong in this test.
                    int type = row.column(i).type();
                    boolean numeric = switch (type) {
                        case TdsTypes.BIT, TdsTypes.BITN, TdsTypes.INT1, TdsTypes.INT2,
                             TdsTypes.INT4, TdsTypes.INT8, TdsTypes.INTN -> true;
                        default -> false;
                    };
                    cells.add(new Cell(row.text(i), numeric ? row.number(i) : 0, row.isNull(i)));
                }
                rows.add(cells);
            });
        }
        return rows;
    }

    /** A whole result: description, two rows, a state change, the end. */
    @Test
    void readsColumnsRowsAndTheRowCount() throws Exception {
        Tokens tokens = new Tokens()
                .colMetadata(3)
                .columnOneByte("id", TdsTypes.INTN, 4, false)
                .columnText("name", TdsTypes.NVARCHAR, 80, true)
                .columnOneByte("flag", TdsTypes.BITN, 1, true)
                .row().cell1(42, 0, 0, 0).cellText("Anna").cell1(1)
                .nbcRow(3, 1).cell1(7, 0, 0, 0).cell1(0)
                .databaseChanged("tempdb", "master")
                .done(TokenStream.DONE_COUNT, 2);

        TokenStream stream = new TokenStream();
        List<List<Cell>> rows = readAll(tokens, stream);

        assertEquals(List.of("id", "name", "flag"),
                stream.columns().stream().map(TdsColumn::name).toList());
        assertFalse(stream.columns().get(0).nullable());
        assertTrue(stream.columns().get(1).nullable());

        assertEquals(2, rows.size());
        assertEquals(42, rows.get(0).get(0).number());
        assertEquals("Anna", rows.get(0).get(1).text());
        assertEquals(1, rows.get(0).get(2).number());

        // The NBCROW: the name is NULL and carries no bytes at all - if the
        // bitmask were misread, the id after it would be wrong too.
        assertEquals(7, rows.get(1).get(0).number());
        assertTrue(rows.get(1).get(1).isNull());
        assertNull(rows.get(1).get(1).text());
        assertEquals(0, rows.get(1).get(2).number());

        assertEquals(2, stream.updateCount());
        assertEquals(2, stream.rowCount());
        assertEquals("tempdb", stream.database());
        assertNull(stream.failure());
    }

    /** A MAX value arrives in chunks and has to come out as one piece. */
    @Test
    void putsTheChunksOfAMaxValueBackTogether() throws Exception {
        Tokens tokens = new Tokens()
                .colMetadata(2)
                .columnText("body", TdsTypes.NVARCHAR, TdsColumn.MAX_SIZE, true)
                .columnOneByte("id", TdsTypes.INTN, 4, false)
                .row().plpText(10, "AB", "CDE").cell1(9, 0, 0, 0)
                .row().plpNull().cell1(8, 0, 0, 0)
                .done(TokenStream.DONE_COUNT, 2);

        TokenStream stream = new TokenStream();
        List<List<Cell>> rows = readAll(tokens, stream);

        assertTrue(stream.columns().get(0).plp(), "MAX was not recognised");
        assertEquals("ABCDE", rows.get(0).get(0).text());
        // The column after it proves that the chunk framing was walked to its
        // end - a byte too few or too many and this would be nonsense.
        assertEquals(9, rows.get(0).get(1).number());
        assertTrue(rows.get(1).get(0).isNull());
        assertEquals(8, rows.get(1).get(1).number());
    }

    /** {@code decimal} carries precision and scale in its description. */
    @Test
    void readsADecimalWithItsScale() throws Exception {
        Tokens tokens = new Tokens()
                .colMetadata(1)
                .columnDecimal("amount", 17, 18, 2)
                .row().cell1(1, 0x39, 0x30, 0, 0)      // +12345
                .row().cell1(0, 0x39, 0x30, 0, 0)      // -12345
                .done(TokenStream.DONE_COUNT, 2);

        TokenStream stream = new TokenStream();
        List<List<Cell>> rows = readAll(tokens, stream);

        assertEquals(18, stream.columns().get(0).precision());
        assertEquals(2, stream.columns().get(0).scale());
        assertEquals("123.45", rows.get(0).get(0).text());
        assertEquals("-123.45", rows.get(1).get(0).text());
    }

    /**
     * The date and time types, which have three shapes in the description:
     * {@code date} carries nothing, {@code time} a scale, and the two combined
     * ones a scale whose value decides how many bytes the value takes.
     */
    @Test
    void readsTheThreeShapesOfTheDateTypes() throws Exception {
        int days = (int) java.time.LocalDate.of(2026, 9, 7).toEpochDay() + 719162;
        int seconds = 14 * 3600 + 30 * 60 + 15;
        int utcSeconds = seconds - 2 * 3600;

        Tokens tokens = new Tokens()
                .colMetadata(4)
                .columnDate("d")
                .columnTime("t", TdsTypes.TIMEN, 0)
                .columnTime("dt2", TdsTypes.DATETIME2N, 3)
                .columnTime("dto", TdsTypes.DATETIMEOFFSETN, 0)
                .row()
                .cell1(le(days, 3))
                .cell1(le(seconds, 3))
                .cell1(concat(le(seconds * 1000L + 250, 4), le(days, 3)))
                .cell1(concat(le(utcSeconds, 3), le(days, 3), le(120, 2)))
                .done(TokenStream.DONE_COUNT, 1);

        TokenStream stream = new TokenStream();
        List<List<Cell>> rows = readAll(tokens, stream);

        assertEquals(3, stream.columns().get(0).size());
        assertEquals(7, stream.columns().get(2).size(), "datetime2(3) takes seven bytes");
        assertEquals("2026-09-07", rows.get(0).get(0).text());
        assertEquals("14:30:15", rows.get(0).get(1).text());
        assertEquals("2026-09-07 14:30:15.250", rows.get(0).get(2).text());
        // datetimeoffset holds UTC on the wire with the offset beside it, so
        // the local time it names is the wire value plus the offset. This
        // used to expect "12:30:15 +02:00" - the UTC fields with the offset
        // written after them, which names a point in time two hours earlier
        // than the bytes do. A real server confirmed the reading: an
        // OffsetDateTime written and read back came out two hours off.
        assertEquals("2026-09-07 14:30:15 +02:00", rows.get(0).get(3).text());
    }

    /** A number as little-endian bytes - the order everything in TDS uses. */
    private static int[] le(long value, int bytes) {
        int[] result = new int[bytes];
        for (int i = 0; i < bytes; i++) {
            result[i] = (int) ((value >>> (i * 8)) & 0xff);
        }
        return result;
    }

    private static int[] concat(int[]... parts) {
        int length = 0;
        for (int[] part : parts) {
            length += part.length;
        }
        int[] result = new int[length];
        int at = 0;
        for (int[] part : parts) {
            System.arraycopy(part, 0, result, at, part.length);
            at += part.length;
        }
        return result;
    }

    /**
     * An error does not end the stream: the server carries on to the DONE, and
     * so does the reader - otherwise the connection would be left with unread
     * bytes and the next statement would read them as its own answer.
     */
    @Test
    void readsToTheEndDespiteAnError() throws Exception {
        Tokens tokens = new Tokens()
                .message(true, 2627, 14, "Violation of PRIMARY KEY constraint")
                .message(true, 3621, 0, "The statement has been terminated.")
                .done(TokenStream.DONE_ERROR, 0);

        TokenStream stream = new TokenStream();
        readAll(tokens, stream);

        assertNotNull(stream.failure());
        assertEquals(2627, stream.failure().getErrorCode());
        assertEquals("23000", stream.failure().getSQLState());
        assertTrue(stream.failure().getMessage().startsWith("Violation of PRIMARY KEY"));
        assertNotNull(stream.failure().getNextException(), "the second error was dropped");
        assertEquals(3621, stream.failure().getNextException().getErrorCode());
    }

    /** An INFO is no error - {@code PRINT} and row counts arrive as one. */
    @Test
    void anInfoIsNotAnError() throws Exception {
        Tokens tokens = new Tokens()
                .message(false, 5701, 0, "Changed database context to 'master'.")
                .done(TokenStream.DONE_COUNT, 0);

        TokenStream stream = new TokenStream();
        readAll(tokens, stream);

        assertNull(stream.failure());
        assertEquals(0, stream.updateCount());
    }

    /**
     * Several statements in one batch: three descriptions, three DONEs. The
     * last count is the one that counts.
     */
    @Test
    void walksThroughABatchOfSeveralResults() throws Exception {
        Tokens tokens = new Tokens()
                .colMetadata(1).columnOneByte("a", TdsTypes.INTN, 4, false)
                .row().cell1(1, 0, 0, 0)
                .done(TokenStream.DONE_COUNT | TokenStream.DONE_MORE, 1)
                .colMetadata(1).columnFixed("b", TdsTypes.INT4)
                .row().raw(2, 0, 0, 0)
                .done(TokenStream.DONE_COUNT | TokenStream.DONE_MORE, 1)
                .done(TokenStream.DONE_COUNT, 5);

        TokenStream stream = new TokenStream();
        List<List<Cell>> rows = readAll(tokens, stream);

        assertEquals(2, rows.size());
        assertEquals(1, rows.get(0).get(0).number());
        // A fixed-length column carries no length byte at all.
        assertEquals(2, rows.get(1).get(0).number());
        assertEquals("b", stream.columns().get(0).name());
        assertEquals(5, stream.updateCount());
    }
}
