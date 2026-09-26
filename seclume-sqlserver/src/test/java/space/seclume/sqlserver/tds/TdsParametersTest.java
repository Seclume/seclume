package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigDecimal;
import java.sql.SQLException;
import java.time.LocalDate;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The parameter encoding, byte for byte.
 *
 * <p>The declaration and the bytes have to agree: the server reads
 * {@code "@P0 int"} and then expects four bytes with an {@code intn} in front
 * of them. Do those two drift apart and the server answers "Error converting
 * data type" - about a statement that looks perfectly right. So both are
 * checked here, together.
 */
class TdsParametersTest {

    /** Reads the written block back as hex, so a mistake names itself. */
    private static String hex(TdsParameters parameters) throws SQLException {
        try (WireBuffer out = new WireBuffer(256)) {
            parameters.writeAll(out);
            StringBuilder text = new StringBuilder();
            for (int i = 0; i < out.position(); i++) {
                text.append(String.format("%02x", out.getByte(i)));
            }
            return text.toString();
        }
    }

    /**
     * The name a value carries: none. The values follow their declaration and
     * are bound by position - a length of zero where "@P0" used to stand.
     */
    private static final String NAME_P0 = "00";

    @Test
    void writesAnIntegerAsIntn() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, 42);
        assertEquals("@P0 int", parameters.declaration());
        assertEquals(NAME_P0 + "00"      // no status flags
                + "26" + "04"            // intn, at most four bytes
                + "04" + "2a000000",     // four bytes, 42 little-endian
                hex(parameters));
    }

    @Test
    void writesALongAsBigint() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, 42L);
        assertEquals("@P0 bigint", parameters.declaration());
        assertEquals(NAME_P0 + "00" + "26" + "08" + "08" + "2a00000000000000",
                hex(parameters));
    }

    /**
     * NULL travels as an nvarchar with the length that means "nothing".
     *
     * <p>The declared width is the full 4000 and not the value's, here as
     * everywhere: a compiled statement keeps its declaration, and one
     * compiled for {@code nvarchar(1)} truncates every later row to a single
     * character without saying so.
     */
    @Test
    void writesNullAsAnEmptyNvarchar() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, null);
        assertEquals("@P0 nvarchar(4000)", parameters.declaration());
        assertEquals(NAME_P0 + "00" + "e7" + "0200" + "0000000000" + "ffff",
                hex(parameters));
    }

    @Test
    void writesTextAsUtf16() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, "Ja");
        assertEquals("@P0 nvarchar(4000)", parameters.declaration());
        assertEquals(NAME_P0 + "00" + "e7" + "0400" + "0000000000"
                + "0400" + "4a006100",
                hex(parameters));
    }

    /** Above 4000 characters the two-byte length is not enough - it goes as MAX. */
    @Test
    void writesLongTextAsMax() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, "x".repeat(5000));
        assertEquals("@P0 nvarchar(max)", parameters.declaration());
        String written = hex(parameters);
        assertEquals(NAME_P0 + "00" + "e7" + "ffff" + "0000000000"
                + "1027000000000000"      // 10000 bytes in total
                + "10270000",             // and one chunk of the same size
                written.substring(0, NAME_P0.length() + 2 + 2 + 4 + 10 + 16 + 8));
        assertEquals("00000000", written.substring(written.length() - 8),
                "the closing zero chunk is missing");
    }

    /**
     * {@code decimal}: sign byte, then sixteen bytes of magnitude - built
     * without BigInteger, which the library does not allow.
     */
    @Test
    void writesADecimalWithSignAndScale() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, new BigDecimal("123.45"));
        assertEquals("@P0 decimal(38,2)", parameters.declaration());
        assertEquals(NAME_P0 + "00" + "6a" + "11" + "26" + "02"
                + "11" + "01" + "39300000" + "00000000" + "00000000" + "00000000",
                hex(parameters));
    }

    @Test
    void marksANegativeDecimal() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, new BigDecimal("-123.45"));
        assertEquals(NAME_P0 + "00" + "6a" + "11" + "26" + "02"
                + "11" + "00" + "39300000" + "00000000" + "00000000" + "00000000",
                hex(parameters));
    }

    /** A date is three bytes of days since 0001-01-01 - and no scale. */
    @Test
    void writesADateAsThreeBytes() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, LocalDate.of(2026, 9, 7));
        assertEquals("@P0 date", parameters.declaration());
        long days = LocalDate.of(2026, 9, 7).toEpochDay() + 719162;
        String expected = NAME_P0 + "00" + "28" + "03"
                + String.format("%02x%02x%02x", days & 0xff, (days >> 8) & 0xff,
                        (days >> 16) & 0xff);
        assertEquals(expected, hex(parameters));
    }

    @Test
    void namesTheParametersInOrder() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, 1);
        parameters.set(2, "a");
        parameters.set(3, true);
        assertEquals("@P0 int,@P1 nvarchar(4000),@P2 bit", parameters.declaration());
        assertEquals(3, parameters.count());
    }

    /** A type the driver cannot encode is refused, not guessed at. */
    @Test
    void refusesATypeItCannotEncode() throws SQLException {
        TdsParameters parameters = new TdsParameters();
        parameters.set(1, new java.util.ArrayList<>());
        SQLException failure = assertThrows(SQLException.class, parameters::declaration);
        assertEquals("22005", failure.getSQLState());
    }
}
