package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The LOB read call, compared byte for byte against a recording.
 *
 * <p>Oracle does not say what it dislikes; it goes quiet or answers something
 * else several round trips later. The only cheap way to be sure a message is
 * right is to build it and hold it against one the reference client sent -
 * this is the same method that found four faults in the login.
 *
 * <p>The recording is {@code docs/protocol/oracle-lob.md}, the first
 * call in it: reading a small CLOB from the beginning, everything at once.
 */
class RecordedLobReadTest {

    /**
     * The TTC part of the recorded request - everything after the packet header.
     *
     * <p>Taken off the recording by machine, never by hand. A hand-copied
     * hexdump in this project once lost three bytes and the test that compared
     * against it stayed green; this constant was wrong by one byte the first
     * time it was typed, and this very test caught it.
     */
    private static final String RECORDED =
            "03600c0001017200000000000000010200000101000100000000000000700002"
            + "020c8280000200000001000000113547000122200001221f0002000203690000"
            + "5c030000080000036aa78962000000000000000000000000bdaecb7600000000"
            + "0000deadbeef0001002200000000002fe7cd0000000000000000000000000000"
            + "000000000001221f0600004c000004ffffffff";

    @Test
    void buildsTheSameBytesAsTheReferenceClient() {
        byte[] expected = unhex(RECORDED); // seclume-allow: a recorded packet, not a secret
        try (WireBuffer locator = new WireBuffer(TtcLob.LOCATOR_LENGTH);
             WireBuffer out = new WireBuffer(256)) {
            // The locator sits in the recorded message itself: after the three
            // bytes of type, function and sequence, and the fixed fields.
            int locatorAt = expected.length - TtcLob.LOCATOR_LENGTH - 5;
            for (int i = 0; i < TtcLob.LOCATOR_LENGTH; i++) {
                locator.putByte(expected[locatorAt + i]);
            }

            TtcLob.putRead(out, 0x0c, locator, 0, TtcLob.LOCATOR_LENGTH, 1, TtcLob.ALL);

            assertEquals(hex(expected), hex(out), "the call does not match the recording");
        }
    }

    private static byte[] unhex(String text) {
        byte[] out = new byte[text.length() / 2]; // seclume-allow: a recorded packet, not a secret
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte b : bytes) {
            text.append(String.format("%02x", b));
        }
        return text.toString();
    }

    private static String hex(WireBuffer buffer) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < buffer.position(); i++) {
            text.append(String.format("%02x", buffer.getByte(i)));
        }
        return text.toString();
    }
}
