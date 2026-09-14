package space.seclume.oracle.net;

import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * The {@code DESCRIBE_INFO} message - what the server says about the columns.
 *
 * <p>Derived from {@code python-oracledb} 4.0.2 as protocol documentation and
 * checked against a recorded exchange with Oracle Free 23ai. Two things in it
 * differ from the reference client's field list, and both were found by the
 * bytes rather than by reading:
 *
 * <ul>
 *   <li>The length that v7 wrote in front of the name is a <b>number</b>, not
 *       a single byte. On a recording where every field is zero and one byte
 *       wide the two are indistinguishable - which is how this parser was
 *       wrong for a while without any test noticing.</li>
 *   <li>Behind the column name there are ten bytes for schema, type name,
 *       column position, the UDS flags and the fields that came with 23.1 -
 *       all zero for a computed column. They are consumed by name where the
 *       name is known and as a fixed run where it is not.</li>
 * </ul>
 *
 * <p>See {@code docs/protocol/oracle.md}. The message ends with a
 * trailer that carries the server's current date - which is what the date in
 * the recording turned out to be, not a message of its own.
 */
public final class TtcDescribe {

    /** A scale byte above this is negative; Oracle writes it unsigned. */
    private static final int SIGNED_BYTE_LIMIT = 127;

    /** The columns and the position just after the message. */
    public record Parsed(List<OracleColumn> columns, int end) {
    }

    private TtcDescribe() {
    }

    /**
     * Reads the message.
     *
     * @param at the position just after the message-type byte
     */
    public static Parsed read(WireBuffer in, int at) {
        Reader reader = new Reader(in, at);
        reader.block();                                // a block that is skipped
        reader.number();                               // largest row size
        int count = (int) reader.number();
        if (count == 0) {
            return new Parsed(List.of(), reader.at());
        }
        reader.byteValue();                            // one byte, meaning unknown

        List<OracleColumn> columns = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            columns.add(readColumn(reader));
        }

        // One number between the last column and the trailer - once, not once
        // per column. That is how it was found: adding it to every column
        // shifted the trailer instead of fixing it.
        reader.number();

        // The trailer: the server's current date, four numbers about the
        // describe cache, and a query key. None of it is needed, but all of it
        // has to be walked over - the row header comes right after.
        reader.block();                                // current date
        reader.number();                               // dcbflag
        reader.number();                               // dcbmdbz
        reader.number();                               // dcbmnpr
        reader.number();                               // dcbmxpr
        reader.block();                                // dcbqcky
        return new Parsed(List.copyOf(columns), reader.at());
    }

    private static OracleColumn readColumn(Reader in) {
        int type = in.byteValue();
        in.byteValue();                                // flags
        int precision = in.byteValue();
        int scale = in.byteValue();
        scale = scale > SIGNED_BYTE_LIMIT ? scale - 256 : scale;
        int bufferSize = (int) in.number();
        in.number();                                   // largest number of array elements
        in.number();                                   // continuation flags
        in.block();                                    // object id
        in.number();                                   // version
        int charset = (int) in.number();
        in.byteValue();                                // character set form
        int maxSize = (int) in.number();
        in.number();                                   // oaccolid
        boolean nullable = in.byteValue() != 0;
        // The name length arrives three times in a row: as a byte, as a
        // number, and as the block prefix in front of the letters. Only the
        // block is used; the other two have to be walked over.
        in.byteValue();                                // name length, once
        in.number();                                   // name length, again
        String name = in.text();
        in.block();                                    // schema
        in.block();                                    // type name
        in.number();                                   // column position
        in.number();                                   // UDS flags
        in.block();                                    // domain schema (23.1)
        in.block();                                    // domain name (23.1)
        in.number();                                   // number of annotations (23.1)
        in.number();                                   // three more, zero here -
        in.number();                                   // again observed rather than
        in.number();                                   // derived
        return new OracleColumn(name, type, precision, scale, bufferSize, maxSize,
                charset, nullable);
    }

    /** Reads Oracle's three shapes: a byte, a length-prefixed number, a block. */
    private static final class Reader {

        /** A length of this means the value arrives in chunks. */
        private static final int CHUNKED = 0xfe;

        private final WireBuffer in;
        private int at;

        Reader(WireBuffer in, int at) {
            this.in = in;
            this.at = at;
        }

        int at() {
            return at;
        }

        int byteValue() {
            return in.getByte(at++) & 0xff;
        }

        long number() {
            int length = byteValue();
            long value = 0;
            for (int i = 0; i < length; i++) {
                value = (value << 8) | byteValue();
            }
            return value;
        }

        /** A block of bytes; beyond 252 it arrives in chunks. */
        int block() {
            int length = byteValue();
            if (length == 0) {
                return 0;
            }
            if (length != CHUNKED) {
                at += length;
                return length;
            }
            int total = 0;
            while (true) {
                int chunk = (int) number();
                if (chunk == 0) {
                    return total;
                }
                at += chunk;
                total += chunk;
            }
        }

        /**
         * A block read as text.
         *
         * <p>Only for names - never for a value that could hold a secret. A
         * column name is protocol text, and it has to become a {@code String}
         * because that is what {@code ResultSetMetaData} hands out.
         */
        String text() {
            int start = at;
            int length = block();
            char[] letters = new char[length]; // seclume-allow: a column name, protocol text and never a secret
            for (int i = 0; i < length; i++) {
                letters[i] = (char) (in.getByte(start + 1 + i) & 0xff);
            }
            return new String(letters); // seclume-allow: a column name, never a secret
        }
    }
}
