package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/**
 * The session recovery data, byte by byte - against what SQL Server 2022
 * acknowledged at a login (taken from a real session) and the layout
 * MS-TDS 2.2.6.4 gives the recovering login.
 */
class RecoveryStateTest {

    /** SQL Server 2022's acknowledgement: state values only, ids 0, 2, 4 to 9. */
    private static final byte[] ACKNOWLEDGED = HexFormat.of().parseHex(
            "000900608114ffe7ffff00020207010401000504ffffffff060100070102"
                    + "080800000000000000000904ffffffff");
    private static final byte[] COLLATION = HexFormat.of().parseHex("0904d00034");

    @Test
    void nothingChangedSendsTheStartAndAnEmptyChange() {
        RecoveryState state = RecoveryState.fromAcknowledgement(ACKNOWLEDGED, "master",
                COLLATION, "us_english");
        assertTrue(state.recoverable());
        byte[] data = state.featureData("master");

        int start = int32(data, 0);
        assertEquals(1 + 12 + 1 + 5 + 1 + 20 + ACKNOWLEDGED.length, start);
        assertEquals(6, data[4], "the database's length in characters");
        assertEquals("master", new String(data, 5, 12,
                java.nio.charset.StandardCharsets.UTF_16LE));
        assertEquals(5, data[17]);
        assertArrayEquals(COLLATION, java.util.Arrays.copyOfRange(data, 18, 23));
        assertArrayEquals(ACKNOWLEDGED, java.util.Arrays.copyOfRange(data, 4 + start
                - ACKNOWLEDGED.length, 4 + start), "the initial values, as acknowledged");
        assertEquals(3, int32(data, 4 + start), "no database, collation or language changed");
        assertEquals(4 + start + 4 + 3, data.length);
    }

    @Test
    void changesAreSentWithTheNewestValueOfEach() {
        RecoveryState state = RecoveryState.fromAcknowledgement(ACKNOWLEDGED, "master",
                COLLATION, "us_english");
        state.apply(5, true, HexFormat.of().parseHex("020207020401ff"));
        state.apply(3, true, HexFormat.of().parseHex("02020000"));   // older: dropped
        state.language("Deutsch");
        byte[] data = state.featureData("tempdb");

        int start = int32(data, 0);
        int at = 4 + start;
        int changed = int32(data, at);
        byte[] change = java.util.Arrays.copyOfRange(data, at + 4, at + 4 + changed);
        assertEquals(6, change[0]);
        assertEquals("tempdb", new String(change, 1, 12,
                java.nio.charset.StandardCharsets.UTF_16LE));
        assertEquals(0, change[13], "the collation did not change");
        assertEquals(7, change[14]);
        assertEquals("Deutsch", new String(change, 15, 14,
                java.nio.charset.StandardCharsets.UTF_16LE));
        assertEquals("020207020401ff", HexFormat.of().formatHex(change, 29, change.length));
    }

    @Test
    void theNewestStatusDecidesWhetherItCanBeRecovered() {
        RecoveryState state = RecoveryState.fromAcknowledgement(ACKNOWLEDGED, "master",
                COLLATION, "us_english");
        state.apply(7, false, new byte[0]);
        assertFalse(state.recoverable());
        state.apply(6, true, new byte[0]);              // older than the "no"
        assertFalse(state.recoverable());
        state.reset();
        assertTrue(state.recoverable(), "a reset session starts over");
        assertEquals(3, int32(state.featureData("master"),
                4 + int32(state.featureData("master"), 0)));
    }

    @Test
    void aLongValueHasItsLengthInFourBytes() {
        RecoveryState state = RecoveryState.fromAcknowledgement(new byte[0], "", new byte[0], "");
        byte[] value = new byte[300];
        java.util.Arrays.fill(value, (byte) 7);
        byte[] set = new byte[2 + 4 + 300];
        set[0] = 9;
        set[1] = (byte) 0xff;
        set[2] = (byte) (300 & 0xff);
        set[3] = (byte) (300 >>> 8);
        System.arraycopy(value, 0, set, 6, 300);
        state.apply(1, true, set);
        byte[] data = state.featureData("");
        int start = int32(data, 0);
        assertEquals(3, start);
        int changed = int32(data, 4 + start);
        assertEquals(3 + 2 + 4 + 300, changed);
    }

    @Test
    void aShortAcknowledgementIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> RecoveryState.fromAcknowledgement(
                HexFormat.of().parseHex("0009006081"), "master", COLLATION, "us_english"));
    }

    private static int int32(byte[] data, int at) {
        return (data[at] & 0xff) | (data[at + 1] & 0xff) << 8 | (data[at + 2] & 0xff) << 16
                | (data[at + 3] & 0xff) << 24;
    }
}
