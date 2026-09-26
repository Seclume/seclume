package space.seclume.oracle.net;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

/**
 * The document inside an {@code XMLType} image.
 *
 * <p>An {@code XMLType} arrives as a pickled object: a header - flags, a
 * version, a length, and unless a flag says otherwise a prefix segment to skip
 * - then a byte of XML version, four bytes of XML flags, and the document. The
 * flags say whether the document is there as text or only as a LOB locator;
 * this reads the first and refuses the second by name. The layout follows
 * python-oracledb 4.0.2 (UPL-1.0 or Apache-2.0; see {@code PROVENANCE.md}) and
 * is held against the server's own {@code getClobVal()} by a test.
 */
public final class OracleXml {

    private static final int NO_PREFIX_SEGMENT = 0x04;
    private static final int LONG_LENGTH = 0xfe;
    private static final int XML_AS_LOB = 0x0001;
    private static final int XML_AS_TEXT = 0x0004;
    private static final int SKIP_NEXT_FOUR = 0x100000;

    private OracleXml() {
    }

    /** The document in the image at {@code at}. */
    public static String fromImage(MemorySegment in, long at, int length) throws SQLException {
        long end = at + length;
        long p = at;
        int flags = u8(in, p++, end);
        p++;                                                   // image version
        p = skipLength(in, p, end);
        if ((flags & NO_PREFIX_SEGMENT) == 0) {
            long[] prefix = readLength(in, p, end);
            p = prefix[1] + prefix[0];
        }
        p++;                                                   // XML version
        int xmlFlags = (u8(in, p, end) << 24) | (u8(in, p + 1, end) << 16)
                | (u8(in, p + 2, end) << 8) | u8(in, p + 3, end);
        p += 4;
        if ((xmlFlags & SKIP_NEXT_FOUR) != 0) {
            p += 4;
        }
        if ((xmlFlags & XML_AS_TEXT) != 0) {
            if (p > end) {
                throw new SQLException("an XMLType image ends before its document", "22000");
            }
            return new String(in.asSlice(p, end - p).toArray(ValueLayout.JAVA_BYTE), // seclume-allow: user payload requested as text, not a secret
                    StandardCharsets.UTF_8);
        }
        if ((xmlFlags & XML_AS_LOB) != 0) {
            throw new SQLException("this XMLType is stored as a LOB, which this driver does not "
                    + "read yet - select xmlserialize(document ... as clob) instead", "0A000");
        }
        throw new SQLException("an XMLType image with flags 0x" + Integer.toHexString(xmlFlags)
                + " is not one this driver reads", "0A000");
    }

    private static long skipLength(MemorySegment in, long p, long end) throws SQLException {
        return u8(in, p, end) == LONG_LENGTH ? p + 5 : p + 1;
    }

    /** A length - one byte, or 0xFE and four - and where what follows it starts. */
    private static long[] readLength(MemorySegment in, long p, long end) throws SQLException {
        int first = u8(in, p, end);
        if (first != LONG_LENGTH) {
            return new long[] {first, p + 1};
        }
        long value = ((long) u8(in, p + 1, end) << 24) | (u8(in, p + 2, end) << 16)
                | (u8(in, p + 3, end) << 8) | u8(in, p + 4, end);
        return new long[] {value, p + 5};
    }

    private static int u8(MemorySegment in, long at, long end) throws SQLException {
        if (at >= end) {
            throw new SQLException("an XMLType image ends at byte " + at + " of " + end,
                    "22000");
        }
        return in.get(ValueLayout.JAVA_BYTE, at) & 0xff;
    }
}
