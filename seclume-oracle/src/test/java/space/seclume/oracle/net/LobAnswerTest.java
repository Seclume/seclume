package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.WireBuffer;

/**
 * The answers to LOB calls, byte for byte as Oracle Database Free sent them.
 *
 * <p>A write and a free are answered with the locator alone; a length (and a
 * read, and a create) with the locator and a number behind it. The status
 * message that follows carries a counter the server raises with every call,
 * and its low byte took every value in turn - which is how reading a number
 * that is not there failed once in 256 writes and never when anybody looked.
 */
class LobAnswerTest {

    /** The 38 bytes of a temporary CLOB's locator, as the server returned it. */
    private static final int[] LOCATOR = {
        0x00, 0x01, 0x82, 0x08, 0x80, 0x01, 0x00, 0x02, 0xe8, 0x4c,
        0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x01, 0x03, 0x69,
        0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xbd, 0xae,
        0xcb, 0x76, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    };

    /** The status behind it; the sixth byte is the low byte of the call counter. */
    private static int[] status(int counter) {
        int[] status = {0x04, 0x01, 0x01, 0x02, 0x1e, counter, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d};
        return status;
    }

    private static WireBuffer answer(int[] amount, int counter) {
        WireBuffer in = new WireBuffer(128);
        in.putByte((byte) TtcMessage.TYPE_PARAMETER);
        in.putByte((byte) 0x00);
        in.putByte((byte) LOCATOR.length);
        for (int b : LOCATOR) {
            in.putByte((byte) b);
        }
        for (int b : amount) {
            in.putByte((byte) b);
        }
        for (int b : status(counter)) {
            in.putByte((byte) b);
        }
        return in;
    }

    /**
     * Every value the counter's low byte takes, and 7 - ROW_DATA - among
     * them: the one that used to fail the write.
     */
    @ParameterizedTest
    @ValueSource(ints = {0x07, 0x04, 0x08, 0x06, 0x8a, 0x00, 0xff})
    void aWriteIsAnsweredWithTheLocatorAloneWhateverTheCounterSays(int counter)
            throws Exception {
        try (WireBuffer in = answer(new int[0], counter);
             WireBuffer sink = new WireBuffer(16)) {
            TtcLob.Answer answer = TtcLob.read(in, 0, in.position(), sink, false);
            assertFalse(answer.tail().isFailure(), "a write that worked read as a failure");
            assertEquals(3, answer.locatorAt());
            assertEquals(LOCATOR.length, answer.locatorLength());
        }
    }

    @Test
    void aLengthCarriesTheNumberBehindTheLocator() throws Exception {
        // 200 000 = 0x030d40, three digits.
        try (WireBuffer in = answer(new int[] {0x03, 0x03, 0x0d, 0x40}, 0x07);
             WireBuffer sink = new WireBuffer(16)) {
            TtcLob.Answer answer = TtcLob.read(in, 0, in.position(), sink, true);
            assertEquals(200_000, answer.reported());
            assertFalse(answer.tail().isFailure());
        }
    }
}
