package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * A column description whose name arrives in chunks with a length no buffer
 * holds. Found by the nightly fuzz run on 27.09.2026: the chunk length
 * {@code FF FF FF 70}, read as a number and cast to an int, is -144, and it
 * reached {@code new char[-144]}. It has to end as {@link WireBuffer.Truncated},
 * which the session turns into a SQLException.
 */
class TtcDescribeMalformedTest {

    /**
     * Where the description starts in the buffer. The old code moved its
     * position back by the negative chunk, and only a position still inside the
     * buffer - landing on a zero, which ends the chunks - reached the array with
     * the negative total. The fuzz case had a long message in front of it.
     */
    private static final int AT = 256;

    /** Zeroes, then one column with every field zero up to its name, then {@code name}. */
    private static WireBuffer describe(int... name) {
        int[] head = {
            0x00,                   // largest row size
            0x01, 0x01,             // one column
            0x00,                   // a byte, meaning unknown
            0x01, 0x00, 0x00, 0x00, // type, flags, precision, scale
            0x00, 0x00, 0x00,       // buffer size, array elements, continuation
            0x00,                   // no object id
            0x00, 0x00,             // version, charset
            0x00,                   // charset form
            0x00, 0x00,             // max size, oaccolid
            0x00,                   // nullable
            0x00, 0x00,             // the name length, as a byte and as a number
        };
        WireBuffer in = new WireBuffer(AT + head.length + name.length + 64);
        for (int i = 0; i < AT; i++) {
            in.putByte((byte) 0);
        }
        for (int b : head) {
            in.putByte((byte) b);
        }
        for (int b : name) {
            in.putByte((byte) b);
        }
        for (int i = 0; i < 32; i++) {
            in.putByte((byte) 0);
        }
        in.position(0);
        in.limit(AT + head.length + name.length + 32);
        return in;
    }

    @Test
    void aChunkThatTurnsNegativeIsRefused() {
        // chunked, then a chunk length of four bytes: FF FF FF 70
        try (WireBuffer in = describe(0xfe, 0x04, 0xff, 0xff, 0xff, 0x70)) {
            assertThrows(WireBuffer.Truncated.class, () -> TtcDescribe.read(in, AT, false));
        }
    }

    @Test
    void aChunkLongerThanTheBufferIsRefusedBeforeAnArrayIsMade() {
        // 0x7FFFFFF0 bytes: positive, and two gigabytes of char[] if it were believed
        try (WireBuffer in = describe(0xfe, 0x04, 0x7f, 0xff, 0xff, 0xf0, 0x00)) {
            assertThrows(WireBuffer.Truncated.class, () -> TtcDescribe.read(in, AT, false));
        }
    }
}
