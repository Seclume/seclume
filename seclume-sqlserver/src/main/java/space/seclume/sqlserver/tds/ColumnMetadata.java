package space.seclume.sqlserver.tds;

import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * Reads the {@code COLMETADATA} token.
 *
 * <p>The token is the key to everything that follows: after it come rows whose
 * bytes cannot be read without it. Its own layout depends on the type of each
 * column, which is why this cannot be a table of fixed offsets but has to be a
 * small parser.
 *
 * <p>The awkward parts, in the order they bite:
 *
 * <ul>
 *   <li>Text types carry a five-byte collation that has to be skipped, binary
 *       ones do not - the same length field, a different tail.</li>
 *   <li>{@code decimal} carries precision and scale, {@code time},
 *       {@code datetime2} and {@code datetimeoffset} carry a scale and
 *       <b>no</b> length, and {@code date} carries neither - three shapes for
 *       what looks like one family.</li>
 *   <li>{@code text}, {@code ntext} and {@code image} are followed by a table
 *       name of as many parts as the server feels like, each with its own
 *       length.</li>
 *   <li>A declared size of {@code 0xffff} does not mean 65535 but {@code MAX} -
 *       and changes the framing of every value in that column.</li>
 * </ul>
 *
 * <p>Getting one of these wrong does not produce an error but a shifted read:
 * the next column starts one byte late, and the values turn into plausible
 * nonsense. That is the reason this class exists on its own and is tested on
 * its own.
 */
public final class ColumnMetadata {

    /** A column count of {@code 0xffff} means: this statement returns no columns. */
    private static final int NO_METADATA = 0xffff;
    /** Length of the collation that follows every text type. */
    private static final int COLLATION_SIZE = 5;

    private ColumnMetadata() {
    }

    /**
     * Reads the token content and returns the columns.
     *
     * @param at the position just after the token byte
     */
    public static Parsed read(WireBuffer in, int at) {
        int count = ushort(in, at);
        int p = at + 2;
        if (count == NO_METADATA) {
            return new Parsed(List.of(), p);
        }
        List<TdsColumn> columns = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            p += 4;                                       // UserType
            int flags = ushort(in, p);
            p += 2;
            boolean nullable = (flags & 0x0001) != 0;

            int type = in.getByte(p) & 0xff;
            p++;

            int size = 0;
            int precision = 0;
            int scale = 0;
            boolean plp = false;

            int fixed = TdsTypes.fixedLength(type);
            if (fixed >= 0) {
                size = fixed;
            } else if (type == TdsTypes.DATEN) {
                // The only variable-length type without anything in the
                // description at all - the value carries its own length byte.
                size = 3;
            } else if (type == TdsTypes.TIMEN || type == TdsTypes.DATETIME2N
                    || type == TdsTypes.DATETIMEOFFSETN) {
                scale = in.getByte(p) & 0xff;
                p++;
                size = timeSize(type, scale);
            } else if (TdsTypes.hasFourByteLength(type)) {
                size = in.getIntLe(p);
                p += 4;
                if (type == TdsTypes.TEXT || type == TdsTypes.NTEXT) {
                    p += COLLATION_SIZE;
                }
                p = skipTableName(in, p);
            } else if (type == TdsTypes.XML) {
                p = skipXmlInfo(in, p);
                size = TdsColumn.MAX_SIZE;
                plp = true;
            } else if (TdsTypes.hasTwoByteLength(type)) {
                size = ushort(in, p);
                p += 2;
                if (type == TdsTypes.BIGCHAR || type == TdsTypes.BIGVARCHAR
                        || type == TdsTypes.NCHAR || type == TdsTypes.NVARCHAR) {
                    p += COLLATION_SIZE;
                }
                plp = size == TdsColumn.MAX_SIZE;
            } else {
                size = in.getByte(p) & 0xff;
                p++;
                if (type == TdsTypes.DECIMAL || type == TdsTypes.DECIMALN
                        || type == TdsTypes.NUMERIC || type == TdsTypes.NUMERICN) {
                    precision = in.getByte(p) & 0xff;
                    scale = in.getByte(p + 1) & 0xff;
                    p += 2;
                }
            }

            int nameChars = in.getByte(p) & 0xff;
            String name = readName(in, p + 1, nameChars);
            p += 1 + nameChars * 2;

            columns.add(new TdsColumn(name, type, size, precision, scale, nullable, plp));
        }
        return new Parsed(List.copyOf(columns), p);
    }

    /**
     * How many bytes a time value takes at the given scale: three up to scale
     * 2, four up to 4, five beyond that - plus the date for the two types that
     * carry one.
     */
    static int timeSize(int type, int scale) {
        int timeBytes = scale <= 2 ? 3 : scale <= 4 ? 4 : 5;
        return switch (type) {
            case TdsTypes.TIMEN -> timeBytes;
            case TdsTypes.DATETIME2N -> timeBytes + 3;
            case TdsTypes.DATETIMEOFFSETN -> timeBytes + 5;
            default -> timeBytes;
        };
    }

    /** The column name in UTF-16LE. */
    private static String readName(WireBuffer in, int at, int chars) {
        char[] text = new char[chars]; // seclume-allow: a column name, protocol text and never a secret
        for (int i = 0; i < chars; i++) {
            text[i] = (char) ((in.getByte(at + i * 2) & 0xff)
                    | ((in.getByte(at + i * 2 + 1) & 0xff) << 8));
        }
        return new String(text); // seclume-allow: a column name, never a secret
    }

    /** {@code text}, {@code ntext} and {@code image} name their table, in parts. */
    private static int skipTableName(WireBuffer in, int at) {
        int parts = in.getByte(at) & 0xff;
        int p = at + 1;
        for (int i = 0; i < parts; i++) {
            int chars = ushort(in, p);
            p += 2 + chars * 2;
        }
        return p;
    }

    /** {@code xml} may name a schema collection - three strings, or none. */
    private static int skipXmlInfo(WireBuffer in, int at) {
        int present = in.getByte(at) & 0xff;
        int p = at + 1;
        if (present == 0) {
            return p;
        }
        p += 1 + (in.getByte(p) & 0xff) * 2;              // database
        p += 1 + (in.getByte(p) & 0xff) * 2;              // owning schema
        int chars = ushort(in, p);
        p += 2 + chars * 2;                               // schema collection
        return p;
    }

    private static int ushort(WireBuffer in, int at) {
        return (in.getByte(at) & 0xff) | ((in.getByte(at + 1) & 0xff) << 8);
    }

    /** The columns and the position just after the token. */
    public record Parsed(List<TdsColumn> columns, int end) {
    }
}
