package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * Answers of an Oracle 11g XE server (11.2.0.2, TTC field version 6), as
 * this driver received them.
 *
 * <p>Three things differ from 12.1 on, and each of them alone made a query
 * on 11g fail or hang: a column description without {@code oaccolid}, return
 * parameters that carry a key/value pair, and an error message without the
 * wide error number and row count.
 */
class Ttc11gAnswerTest {

    private static final int FIELD_VERSION_11_2 = 6;

    /** {@code select 1 from dual}: description, one row, parameters, ORA-01403. */
    private static final String SELECT_ONE =
            "1017b4c94d7dfbbcf023ed720251c896e0aa787e0a090a271d0102010151020000810102"
            + "0000000000000001010101013100000000010707787e0a090a2e3400021fe80102010200"
            + "062201010001640000000702c10208010603071a3b00010200000000010100010b0b8000"
            + "85d8b73c3c8000000001a3000401010104010102057b0000010200030000000000000000"
            + "000000000300010100000000194f52412d30313430333a206e6f206461746120666f756e"
            + "640a";

    /** {@code select * from nonexistent_tab}: ORA-00942 and its text. */
    private static final String TABLE_MISSING =
            "0401010104000203ae00000102010e030000000000000000000000000300000000000028"
            + "4f52412d30303934323a207461626c65206f72207669657720646f6573206e6f74206578"
            + "6973740a";

    @Test
    void readsTheRowOfASelectOn11g() throws Exception {
        List<String> values = new ArrayList<>();
        TtcResult result = read(SELECT_ONE, values);
        assertEquals(List.of("1"), result.columns().stream().map(OracleColumn::name).toList());
        assertEquals(1, result.rowCount());
        assertEquals(List.of("1"), values);
        assertTrue(result.ended(), "the walk reaches the error message behind the parameters");
        assertTrue(result.isExhausted(), "ORA-01403 ends the result");
    }

    @Test
    void readsTheErrorNumberAndTextOn11g() throws Exception {
        TtcResult result = read(TABLE_MISSING, new ArrayList<>());
        assertEquals(942, result.errorNumber());
        assertEquals("ORA-00942: table or view does not exist", result.errorText());
    }

    /**
     * {@code select rpad('a', 300, 'b') as x from dual}, around its value:
     * the value itself arrives as {@code fe ff <255 bytes> 2d <45 bytes> 00},
     * every chunk length a single byte.
     */
    private static final String LONG_VALUE_BEFORE =
            "10172629f60f76de03e0c76eca86d6633c9d787e0a090a3c0e02012c010151018000"
            + "0002012c000000000203690102012c01010101015800000000010707787e0a090a3c"
            + "0e00021fe801020102000622010100016400000007";
    private static final String LONG_VALUE_AFTER =
            "0008010603071daa00010200000000010100010b0b800085d8b73c3c8000000001a3"
            + "000401010104010102057b0000010201250300000000000000000000000003000101"
            + "00000000194f52412d30313430333a206e6f206461746120666f756e640a";

    private static String longValueAnswer() {
        StringBuilder hex = new StringBuilder(LONG_VALUE_BEFORE).append("feff61");
        hex.append("62".repeat(254)).append("2d").append("62".repeat(45));
        return hex.append(LONG_VALUE_AFTER).toString();
    }

    @Test
    void readsAValueInSingleByteChunks() throws Exception {
        List<String> values = new ArrayList<>();
        TtcResult result = read(longValueAnswer(), values, false);
        assertEquals(List.of("a" + "b".repeat(299)), values);
        assertTrue(result.isExhausted());
    }

    @Test
    void aTrialWalkLeavesTheAnswerAsItFoundIt() throws Exception {
        // Before 23ai the end of an answer is found by walking it once on
        // trial; the real walk after it has to see the bytes the server sent.
        List<String> values = new ArrayList<>();
        read(longValueAnswer(), values, true);
        assertEquals(List.of("a" + "b".repeat(299)), values);
    }

    @Test
    void writesChunksTheWayTheServerReadsThem() {
        byte[] value = new byte[300];
        try (WireBuffer out = new WireBuffer(512)) {
            TtcParameters.putChunked(out, java.lang.foreign.MemorySegment.ofArray(value), 0,
                    value.length, false);
            // fe, then 64-byte chunks with a one-byte length, then a zero
            assertEquals(1 + 5 + 300 + 1, out.position());
            assertEquals((byte) 0xfe, out.getByte(0));
            assertEquals(64, out.getByte(1));
            assertEquals(300 - 4 * 64, out.getByte(1 + 4 * 65));
            assertEquals(0, out.getByte(out.position() - 1));
        }
        try (WireBuffer out = new WireBuffer(512)) {
            TtcParameters.putChunked(out, java.lang.foreign.MemorySegment.ofArray(value), 0,
                    value.length, true);
            // fe, one chunk whose length is a number (02 01 2c), then a zero
            assertEquals(1 + 3 + 300 + 1, out.position());
            assertEquals(2, out.getByte(1));
        }
    }

    @Test
    void anExecuteCarriesAsManyTrailingZeroesAsTheServerReads() {
        assertEquals(5, TtcQuery.tailZeroes(FIELD_VERSION_11_2));
        assertEquals(8, TtcQuery.tailZeroes(TtcQuery.FIELD_VERSION_12_1));
        assertEquals(13, TtcQuery.tailZeroes(TtcQuery.FIELD_VERSION_12_2));
        assertEquals(15, TtcQuery.tailZeroes(TtcQuery.FIELD_VERSION_12_2_EXT1));
        assertEquals(15, TtcQuery.tailZeroes(TtcDataTypes.FIELD_VERSION));
    }

    private static TtcResult read(String hex, List<String> values) throws Exception {
        return read(hex, values, false);
    }

    private static TtcResult read(String hex, List<String> values, boolean trialFirst)
            throws Exception {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        try (WireBuffer in = new WireBuffer(bytes.length + 16)) {
            for (byte b : bytes) {
                in.putByte(b);
            }
            in.position(0);
            in.limit(bytes.length);
            if (trialFirst) {
                TtcResult trial = new TtcResult().fieldVersion(FIELD_VERSION_11_2).trial();
                trial.read(in, 0, bytes.length, null);
                assertTrue(trial.ended());
            }
            TtcResult result = new TtcResult().fieldVersion(FIELD_VERSION_11_2);
            result.read(in, 0, bytes.length, row -> {
                for (int i = 0; i < row.columnCount(); i++) {
                    values.add(row.text(i));
                }
            });
            return result;
        }
    }
}
