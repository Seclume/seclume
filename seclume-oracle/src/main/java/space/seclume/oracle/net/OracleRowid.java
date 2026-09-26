package space.seclume.oracle.net;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * A {@code ROWID} cell as the eighteen characters Oracle prints -
 * {@code AAAYPMAAYAAAAo0AAA}: object, file, block and slot in Oracle's own
 * base-64 alphabet, six, three, six and three characters wide.
 *
 * <p>The cell holds the five numbers as they came off the wire, each a count
 * byte and that many big-endian bytes (see {@code TtcRow.readRowid}); the
 * third is not used. The layout follows python-oracledb 4.0.2 (UPL-1.0 or
 * Apache-2.0; see {@code PROVENANCE.md}) and is held against the server's own
 * {@code rowidtochar} by a test.
 */
public final class OracleRowid {

    private static final String ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private OracleRowid() {
    }

    /** The printed form of the rowid in the cell at {@code at}. */
    public static String toText(MemorySegment in, long at, int length) {
        long[] fields = new long[5];
        long p = at;
        for (int i = 0; i < 5 && p < at + length; i++) {
            int count = in.get(ValueLayout.JAVA_BYTE, p) & 0x7f;
            p++;
            long value = 0;
            for (int b = 0; b < count; b++) {
                value = (value << 8) | (in.get(ValueLayout.JAVA_BYTE, p + b) & 0xff);
            }
            fields[i] = value;
            p += count;
        }
        StringBuilder text = new StringBuilder(18); // seclume-allow: a row address, never a secret
        put(text, fields[0], 6);             // object
        put(text, fields[1], 3);             // file
        put(text, fields[3], 6);             // block
        put(text, fields[4], 3);             // slot
        return text.toString();
    }

    /**
     * A {@code UROWID} cell - the address as raw bytes, not as five numbers.
     *
     * <p>A first byte of 1 is a physical address, object, file, block and
     * slot in four, two, four and two bytes, printed as a {@code ROWID} is. Any
     * other is a logical one - a row of an index-organized table, addressed by
     * its key - which Oracle prints as a star and the bytes after the first
     * in the same alphabet, unpadded.
     */
    public static String fromUrowid(MemorySegment in, long at, int length) {
        StringBuilder text = new StringBuilder(); // seclume-allow: a row address, never a secret
        if (length == 13 && byteAt(in, at) == 1) {
            put(text, number(in, at + 1, 4), 6);
            put(text, number(in, at + 5, 2), 3);
            put(text, number(in, at + 7, 4), 6);
            put(text, number(in, at + 11, 2), 3);
            return text.toString();
        }
        text.append('*');
        for (long p = at + 1; p < at + length; p += 3) {
            int left = (int) Math.min(3, at + length - p);
            long group = number(in, p, left) << (8 * (3 - left));
            for (int i = 0; i <= left; i++) {
                text.append(ALPHABET.charAt((int) ((group >>> (18 - 6 * i)) & 0x3f)));
            }
        }
        return text.toString();
    }

    private static long number(MemorySegment in, long at, int bytes) {
        long value = 0;
        for (int i = 0; i < bytes; i++) {
            value = (value << 8) | byteAt(in, at + i);
        }
        return value;
    }

    private static int byteAt(MemorySegment in, long at) {
        return in.get(ValueLayout.JAVA_BYTE, at) & 0xff;
    }

    private static void put(StringBuilder text, long value, int width) {
        for (int i = width - 1; i >= 0; i--) {
            text.append(ALPHABET.charAt((int) ((value >>> (6 * i)) & 0x3f)));
        }
    }
}
