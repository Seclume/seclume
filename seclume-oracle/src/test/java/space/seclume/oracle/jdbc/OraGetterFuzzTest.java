package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.junit.FuzzTest;

import space.seclume.internal.WireBuffer;
import space.seclume.oracle.net.OracleColumn;
import space.seclume.oracle.net.TtcRow;
import space.seclume.tck.fuzz.GetterSweep;

/**
 * Oracle's answers cannot be built by hand far enough to reach a row - see
 * OracleDecoderFuzzTest - so the getters are swept one layer down: a row of
 * one cell, its bytes whatever the input says, under every scalar type the
 * driver converts. Every getter may refuse with an SQLException and with
 * nothing else: not an ArithmeticException from a NUMBER of 200 digits, not a
 * DateTimeException from month 13 or an offset of 30 hours, not an
 * IllegalArgumentException from a code point beyond Unicode.
 */
class OraGetterFuzzTest {

    /** The types whose values arrive inline; LOBs, JSON, vectors and cursors need a session. */
    private static final int[] TYPES = {
        OracleColumn.TYPE_NUMBER, OracleColumn.TYPE_VARCHAR, OracleColumn.TYPE_CHAR,
        OracleColumn.TYPE_DATE, OracleColumn.TYPE_RAW, OracleColumn.TYPE_ROWID,
        OracleColumn.TYPE_UROWID, OracleColumn.TYPE_INTERVAL_YM, OracleColumn.TYPE_INTERVAL_DS,
        OracleColumn.TYPE_TIMESTAMP, OracleColumn.TYPE_TIMESTAMP_ZONE,
        OracleColumn.TYPE_TIMESTAMP_LOCAL, OracleColumn.TYPE_BINARY_FLOAT,
        OracleColumn.TYPE_BINARY_DOUBLE, OracleColumn.TYPE_BOOLEAN, OracleColumn.TYPE_LONG,
        OracleColumn.TYPE_LONG_RAW};

    /** AL32UTF8, the character set the driver logs in with. */
    private static final int AL32UTF8 = 873;

    private static WireBuffer cell(byte[] value) {
        WireBuffer in = new WireBuffer(value.length + 1);
        in.putByte((byte) value.length);
        for (byte b : value) {
            in.putByte(b);
        }
        return in;
    }

    private static void sweep(int type, int scale, byte[] value) {
        OracleColumn column = new OracleColumn("N", type, 38, scale, 255, 255, AL32UTF8, true);
        try (WireBuffer in = cell(value)) {
            TtcRow row = new TtcRow(in, List.of(column));
            try {
                row.read(0, null);
            } catch (WireBuffer.Truncated cut) {
                // The row reader's refusal of a cell cut short - the session makes
                // it a broken connection; OracleDecoderFuzzTest holds it to that.
                return;
            }
            try (OraResultBlock block = new OraResultBlock(List.of(column))) {
                block.append(row);
                try (OraResultSet rows = new OraResultSet(block, null)) {
                    assertTrue(rows.next());
                    for (GetterSweep.Getter getter : GetterSweep.GETTERS) {
                        try {
                            getter.read(rows, 1);
                        } catch (SQLException refused) {
                            // a value this getter does not take: allowed
                        }
                    }
                }
            }
        } catch (SQLException refused) {
            // reading the row may refuse it, the same way
        }
    }

    private static String text(int... value) throws SQLException {
        byte[] bytes = new byte[value.length];
        for (int i = 0; i < value.length; i++) {
            bytes[i] = (byte) value[i];
        }
        OracleColumn column = new OracleColumn("N", OracleColumn.TYPE_VARCHAR, 0, 0, 255, 255,
                AL32UTF8, true);
        try (WireBuffer in = cell(bytes)) {
            TtcRow row = new TtcRow(in, List.of(column));
            row.read(0, null);
            try (OraResultBlock block = new OraResultBlock(List.of(column))) {
                block.append(row);
                try (OraResultSet rows = new OraResultSet(block, null)) {
                    assertTrue(rows.next());
                    return rows.getString(1);
                }
            }
        }
    }

    private static boolean allReplaced(String text) {
        return !text.isEmpty() && text.chars().allMatch(c -> c == 0xfffd);
    }

    /**
     * RFC 3629: what is not UTF-8 is a replacement character - never a second
     * spelling of a character, never a lone surrogate, never an exception out
     * of getString.
     */
    @Test
    void textThatIsNotUtf8IsReplacedNotReadOrThrown() throws SQLException {
        assertEquals("Grüße 😀", text('G', 'r', 0xc3, 0xbc, 0xc3, 0x9f, 'e',
                ' ', 0xf0, 0x9f, 0x98, 0x80));
        assertFalse(text(0xc0, 0xaf).contains("/"), "an overlong '/' was read as one");
        assertFalse(text(0xe0, 0x80, 0xa7).contains("'"), "an overlong quote was read as one");
        assertTrue(text(0xed, 0xa0, 0x80).chars().noneMatch(c -> Character.isSurrogate((char) c)),
                "a lone surrogate");
        assertTrue(allReplaced(text(0xf4, 0x90, 0x80, 0x80)), "beyond U+10FFFF");
        assertTrue(allReplaced(text(0xf8, 0x88, 0x80, 0x80, 0x80)), "a five-byte form");
        assertTrue(allReplaced(text(0xff, 0x87, 0xff, 0x91)), "the fuzzer's input");
    }

    /** Values a converter has an edge at, under every type. */
    @Test
    void everyGetterSurvivesAnAwkwardValue() {
        byte[][] values = {
            {}, {(byte) 0x80}, {(byte) 0xc1, 0x02}, {0x3e, 0x64, 0x66},       // NUMBER: zero, 1, -1
            {(byte) 0xff, 0x65}, {0x00},                                       // beyond range
            {0x78, 0x7e, 0x0b, 0x1a, 0x08, 0x3c, 0x3c},                       // DATE 2026-11-26 07:59:59
            {0x78, 0x7e, 0x0d, 0x2d, 0x1a, 0x3e, 0x3e},                       // month 13, hour 25
            {0x78, 0x7e, 0x0b},                                                // DATE cut short
            {0x78, 0x7e, 0x0b, 0x1a, 0x08, 0x3c, 0x3c, 0x3b, (byte) 0x9a, (byte) 0xca, 0x00},
            {0x78, 0x7e, 0x0b, 0x1a, 0x08, 0x3c, 0x3c, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                0x7f, 0x7f},                                                   // nanos and zone beyond
            "12x".getBytes(), "1e999999999".getBytes(), "123e4567".getBytes(),
            new byte[250]};
        for (int type : TYPES) {
            for (byte[] value : values) {
                for (int scale : new int[] {0, -127, 127}) {
                    sweep(type, scale, value);
                }
            }
        }
    }

    @FuzzTest(maxDuration = "60s")
    void coverageGuided(byte[] input) {
        if (input.length < 2) {
            return;
        }
        int type = TYPES[(input[0] & 0xff) % TYPES.length];
        int scale = input[1];
        byte[] value = java.util.Arrays.copyOfRange(input, 2, Math.min(input.length, 252));
        sweep(type, scale, value);
    }
}
