package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The bytes that give a cursor back, against the ones Oracle's own client
 * sends.
 *
 * <p>The expected value is not this code agreeing with itself: it is a
 * capture. {@code python-oracledb} 4.0.2 was run against our own Oracle
 * instance with {@code PYO_DEBUG_PACKETS=1} and a statement cache of two, and
 * once more with five cursors closed in one go - the second run being the one
 * that tells the count apart from the first cursor number, which a single
 * cursor cannot.
 *
 * <p>A test that only checked our encoder could read its own output back and
 * be satisfied by a format the server has never seen.
 */
class CloseCursorsMessageTest {

    /**
     * Five cursors at once, from the capture:
     *
     * <pre>
     * 0008 : 00 00 11 69 08 00 01 01
     * 0016 : 05 01 01 01 03 01 04 01
     * 0024 : 05 01 06 03 5E 09 00 02
     * </pre>
     *
     * The two bytes before {@code 11} are the data flags and the {@code 03 5E}
     * after it is the execute call this rode in front of - neither belongs to
     * the piggyback.
     */
    @Test
    void fiveCursorsLookLikeTheReferenceClient() {
        try (WireBuffer out = new WireBuffer(64)) {
            TtcClose.putPiggyback(out, 8, new int[] {1, 3, 4, 5, 6, 99}, 5);
            assertEquals("11 69 08 00 01 01 05 01 01 01 03 01 04 01 05 01 06", hex(out));
        }
    }

    /** And one cursor, from the first capture - {@code 11 69 07 ... 01 03}. */
    @Test
    void oneCursorLooksLikeTheReferenceClient() {
        try (WireBuffer out = new WireBuffer(64)) {
            TtcClose.putPiggyback(out, 7, new int[] {3}, 1);
            assertEquals("11 69 07 00 01 01 01 01 03", hex(out));
        }
    }

    private static String hex(WireBuffer buffer) {
        StringBuilder text = new StringBuilder(); // seclume-allow: cursor numbers, not a secret
        for (int i = 0; i < buffer.position(); i++) {
            if (i > 0) {
                text.append(' ');
            }
            text.append(String.format("%02X", buffer.getByte(i)));
        }
        return text.toString();
    }
}
