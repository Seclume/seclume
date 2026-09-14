package space.seclume.mysql.wire;

import space.seclume.internal.WireBuffer;

/**
 * The encodings that show up all over the MySQL protocol.
 *
 * <p>MySQL has two special forms PostgreSQL does not:
 *
 * <ul>
 *   <li><b>length-encoded integer</b> - a number of variable length. A byte
 *       below 251 is the number itself; 0xFC, 0xFD and 0xFE introduce two,
 *       three and eight further bytes. 0xFB means NULL.</li>
 *   <li><b>length-encoded string</b> - such a number, followed by that many
 *       bytes.</li>
 * </ul>
 *
 * <p>This encoding is the reason a MySQL result cannot be skipped through in
 * fixed steps: every cell has to be read in order to know where the next one
 * starts.
 */
public final class MyPackets {

    /** First byte of an OK packet. */
    public static final int OK = 0x00;
    /** First byte of an error packet. */
    public static final int ERR = 0xff;
    /** First byte of an EOF packet - and, with DEPRECATE_EOF, of an OK packet. */
    public static final int EOF = 0xfe;
    /** First byte of an AuthMoreData message. */
    public static final int AUTH_MORE_DATA = 0x01;
    /** First byte of an AuthSwitchRequest message. */
    public static final int AUTH_SWITCH = 0xfe;
    /** The length marker that means NULL. */
    public static final int NULL_LENGTH = 0xfb;

    /** The largest packet the length in the header can express. */
    public static final int MAX_PAYLOAD = 0xffffff;

    private MyPackets() {
    }

    /** Reads a length-encoded number; -1 stands for NULL. */
    public static long readLengthEncoded(WireBuffer in) {
        int first = in.getByte() & 0xff;
        return switch (first) {
            case NULL_LENGTH -> -1;
            case 0xfc -> in.getUnsignedLe(2);
            case 0xfd -> in.getUnsignedLe(3);
            case 0xfe -> in.getUnsignedLe(8);
            default -> first;
        };
    }

    /** Writes a length-encoded number. */
    public static void writeLengthEncoded(WireBuffer out, long value) {
        if (value < 251) {
            out.putByte((byte) value);
        } else if (value < 1 << 16) {
            out.putByte((byte) 0xfc).putUnsignedLe(value, 2);
        } else if (value < 1 << 24) {
            out.putByte((byte) 0xfd).putUnsignedLe(value, 3);
        } else {
            out.putByte((byte) 0xfe).putLongLe(value);
        }
    }

    /**
     * Skips a length-encoded string and returns its length; -1 for NULL. The
     * content stays in the buffer - whoever needs it takes a window onto
     * it.
     */
    public static long skipLengthEncodedString(WireBuffer in) {
        long length = readLengthEncoded(in);
        if (length > 0) {
            in.skip((int) length);
        }
        return length;
    }

    /**
     * Reads a length-encoded string as text.
     *
     * <p>Only for protocol text - column and table names, server banners.
     * Payload and secrets stay in the buffer.
     */
    public static String readLengthEncodedString(WireBuffer in) {
        long length = readLengthEncoded(in);
        return length < 0 ? null : in.readString((int) length);
    }

    /** Writes protocol text with the length in front. */
    public static void writeLengthEncodedString(WireBuffer out, String text) {
        byte[] bytes = text.getBytes(java.nio.charset.StandardCharsets.UTF_8); // seclume-allow: protocol text such as user and schema names, never a secret
        writeLengthEncoded(out, bytes.length);
        out.putBytes(java.lang.foreign.MemorySegment.ofArray(bytes), 0, bytes.length);
    }
}
