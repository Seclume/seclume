package space.seclume.oracle.net;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Oracle's native {@code JSON} type - OSON, a binary format - read back as
 * JSON text.
 *
 * <p>A {@code JSON} column arrives as a LOB locator, and what the LOB holds is
 * not text but a tree: a header, a dictionary of field names, and a segment of
 * nodes that point at each other by offset. This walks the tree and writes
 * the text a {@code json_serialize} would have produced, so that
 * {@code getString} answers with JSON - which is what Hibernate, Jackson and
 * every other caller without ojdbc's own JSON classes can read.
 *
 * <p>The format is derived from python-oracledb 4.0.2 (UPL-1.0 or
 * Apache-2.0; see {@code PROVENANCE.md}), {@code impl/base/oson.pyx}, and held
 * by tests against a live server. Values beyond JSON's own - dates,
 * timestamps, binary - come out as strings, the way {@code json_serialize}
 * writes them; an interval or a vector is refused rather than guessed.
 */
public final class OracleJson {

    private static final int MAGIC_1 = 0xff;
    private static final int MAGIC_2 = 0x4a;
    private static final int MAGIC_3 = 0x5a;
    private static final int VERSION_MAX_FNAME_255 = 1;
    private static final int VERSION_MAX_FNAME_65535 = 3;

    private static final int FLAG_REL_OFFSET_MODE = 0x01;
    private static final int FLAG_NUM_FNAMES_UINT32 = 0x08;
    private static final int FLAG_IS_SCALAR = 0x10;
    private static final int FLAG_NUM_FNAMES_UINT16 = 0x400;
    private static final int FLAG_FNAMES_SEG_UINT32 = 0x800;
    private static final int FLAG_TREE_SEG_UINT32 = 0x1000;
    private static final int FLAG_SEC_FNAMES_SEG_UINT16 = 0x100;

    private static final int TYPE_NULL = 0x30;
    private static final int TYPE_TRUE = 0x31;
    private static final int TYPE_FALSE = 0x32;
    private static final int TYPE_STRING_UINT8 = 0x33;
    private static final int TYPE_NUMBER_UINT8 = 0x34;
    private static final int TYPE_BINARY_DOUBLE = 0x36;
    private static final int TYPE_STRING_UINT16 = 0x37;
    private static final int TYPE_STRING_UINT32 = 0x38;
    private static final int TYPE_TIMESTAMP = 0x39;
    private static final int TYPE_BINARY_UINT16 = 0x3a;
    private static final int TYPE_BINARY_UINT32 = 0x3b;
    private static final int TYPE_DATE = 0x3c;
    private static final int TYPE_TIMESTAMP_TZ = 0x7c;
    private static final int TYPE_TIMESTAMP7 = 0x7d;
    private static final int TYPE_ID = 0x7e;
    private static final int TYPE_BINARY_FLOAT = 0x7f;

    private final MemorySegment in;
    private final long start;
    private final long end;
    private long pos;
    private long treeStart;
    private boolean relativeOffsets;
    private int fieldIdLength;
    private final List<String> fieldNames = new ArrayList<>();

    private OracleJson(MemorySegment in, long at, int length) {
        this.in = in;
        this.start = at;
        this.end = at + length;
        this.pos = at;
    }

    /**
     * The OSON bytes at {@code at} as JSON text.
     *
     * @throws SQLException when the bytes are not OSON, or hold a type that
     *                      JSON text has no spelling for
     */
    public static String toText(MemorySegment in, long at, int length) throws SQLException {
        OracleJson reader = new OracleJson(in, at, length);
        StringBuilder out = new StringBuilder(Math.max(16, length)); // seclume-allow: user payload requested as text, not a secret
        try {
            reader.document(out);
        } catch (IndexOutOfBoundsException e) {
            throw new SQLException("the JSON value ends early - " + length
                    + " bytes, and more were referred to", "22000", e);
        }
        return out.toString();
    }

    private void document(StringBuilder out) throws SQLException {
        if (u8() != MAGIC_1 || u8() != MAGIC_2 || u8() != MAGIC_3) {
            throw new SQLException("not an OSON value: the header is missing", "22000");
        }
        int version = u8();
        if (version != VERSION_MAX_FNAME_255 && version != VERSION_MAX_FNAME_65535) {
            throw new SQLException("OSON version " + version + " is not one this driver reads",
                    "0A000");
        }
        int flags = u16();
        relativeOffsets = (flags & FLAG_REL_OFFSET_MODE) != 0;
        if ((flags & FLAG_IS_SCALAR) != 0) {
            pos += (flags & FLAG_TREE_SEG_UINT32) != 0 ? 4 : 2;     // tree segment size
            node(out);
            return;
        }

        long shortNames;
        if ((flags & FLAG_NUM_FNAMES_UINT32) != 0) {
            shortNames = u32();
            fieldIdLength = 4;
        } else if ((flags & FLAG_NUM_FNAMES_UINT16) != 0) {
            shortNames = u16();
            fieldIdLength = 2;
        } else {
            shortNames = u8();
            fieldIdLength = 1;
        }
        int shortOffsetSize = (flags & FLAG_FNAMES_SEG_UINT32) != 0 ? 4 : 2;
        long shortSegmentSize = shortOffsetSize == 4 ? u32() : u16();

        long longNames = 0;
        long longSegmentSize = 0;
        int longOffsetSize = 4;
        if (version == VERSION_MAX_FNAME_65535) {
            int secondary = u16();
            longOffsetSize = (secondary & FLAG_SEC_FNAMES_SEG_UINT16) != 0 ? 2 : 4;
            longNames = u32();
            longSegmentSize = u32();
        }
        pos += (flags & FLAG_TREE_SEG_UINT32) != 0 ? 4 : 2;         // tree segment size
        pos += 2;                                                    // number of tiny nodes

        names(shortNames, 1, shortOffsetSize, shortSegmentSize, false);
        names(longNames, 2, longOffsetSize, longSegmentSize, true);
        treeStart = pos;
        node(out);
    }

    /**
     * The field-name dictionary: a hash per name (skipped), an offset per
     * name, then the names, each behind its length.
     */
    private void names(long count, int hashSize, int offsetSize, long segmentSize,
            boolean longLength) {
        if (count == 0) {
            return;
        }
        pos += count * hashSize;
        long offsets = pos;
        long segment = offsets + count * offsetSize;
        for (long i = 0; i < count; i++) {
            pos = offsets + i * offsetSize;
            long offset = offsetSize == 2 ? u16() : u32();
            pos = segment + offset;
            int length = longLength ? u16() : u8();
            fieldNames.add(utf8(pos, length));
        }
        pos = segment + segmentSize;
    }

    private void node(StringBuilder out) throws SQLException {
        int type = u8();
        if ((type & 0x80) != 0) {
            container(type, out);
            return;
        }
        switch (type) {
            case TYPE_NULL -> out.append("null");
            case TYPE_TRUE -> out.append("true");
            case TYPE_FALSE -> out.append("false");
            case TYPE_STRING_UINT8 -> string(u8(), out);
            case TYPE_STRING_UINT16 -> string(u16(), out);
            case TYPE_STRING_UINT32 -> string(u32(), out);
            case TYPE_NUMBER_UINT8 -> number(u8(), out);
            case TYPE_BINARY_DOUBLE -> floating(8, out);
            case TYPE_BINARY_FLOAT -> floating(4, out);
            case TYPE_DATE, TYPE_TIMESTAMP7 -> moment(7, out);
            case TYPE_TIMESTAMP -> moment(11, out);
            case TYPE_TIMESTAMP_TZ -> moment(13, out);
            case TYPE_ID -> binary(u8(), out);
            case TYPE_BINARY_UINT16 -> binary(u16(), out);
            case TYPE_BINARY_UINT32 -> binary(u32(), out);
            default -> compact(type, out);
        }
    }

    /** The types that carry their length in the low bits of the type byte. */
    private void compact(int type, StringBuilder out) throws SQLException {
        int high = type & 0xf0;
        if (high == 0x20 || high == 0x60) {                          // number, decimal
            number((type & 0x0f) + 1, out);
        } else if (high == 0x40 || high == 0x50) {                   // integer
            number(type & 0x0f, out);
        } else if ((type & 0xe0) == 0) {                             // short string
            string(type, out);
        } else {
            throw new SQLException("OSON node type 0x" + Integer.toHexString(type)
                    + " is not one this driver reads (an interval, a vector or an "
                    + "extension)", "0A000");
        }
    }

    /**
     * An object or an array: a count, for an object the field ids, then an
     * offset per child into the tree segment.
     *
     * <p>An object may share its field ids with another of the same shape -
     * the rows of an array of records do. Then the node carries an offset to
     * that other object instead of ids of its own, and the ids and the count
     * are read there.
     */
    private void container(int type, StringBuilder out) throws SQLException {
        boolean object = (type & 0x40) == 0;
        long containerOffset = pos - treeStart - 1;
        int childrenBits = type & 0x18;
        long children;
        long fieldIds = 0;
        long offsets;
        if (childrenBits == 0x18) {
            long shared = offset(type);
            offsets = pos;
            pos = treeStart + shared;
            int sharedType = u8();
            children = count(sharedType & 0x18);
            fieldIds = pos;
        } else {
            children = count(childrenBits);
            if (object) {
                fieldIds = pos;
                offsets = pos + fieldIdLength * children;
            } else {
                offsets = pos;
            }
        }
        out.append(object ? '{' : '[');
        for (long i = 0; i < children; i++) {
            if (i > 0) {
                out.append(',');
            }
            if (object) {
                pos = fieldIds;
                long id = switch (fieldIdLength) {
                    case 1 -> u8();
                    case 2 -> u16();
                    default -> u32();
                };
                fieldIds = pos;
                if (id < 1 || id > fieldNames.size()) {
                    throw new SQLException("OSON field id " + id + " is outside the "
                            + fieldNames.size() + " names the value has", "22000");
                }
                quoted(fieldNames.get((int) id - 1), out);
                out.append(':');
            }
            pos = offsets;
            long child = offset(type);
            offsets = pos;
            if (relativeOffsets) {
                child += containerOffset;
            }
            pos = treeStart + child;
            node(out);
        }
        out.append(object ? '}' : ']');
    }

    private long count(int childrenBits) {
        return switch (childrenBits) {
            case 0 -> u8();
            case 0x08 -> u16();
            default -> u32();
        };
    }

    private long offset(int type) {
        return (type & 0x20) != 0 ? u32() : u16();
    }

    private void string(long length, StringBuilder out) {
        quoted(utf8(pos, (int) length), out);
        pos += length;
    }

    private void number(int length, StringBuilder out) {
        out.append(length == 0 ? "0" : OracleNumber.toText(in, pos, length));
        pos += length;
    }

    private void floating(int length, StringBuilder out) throws SQLException {
        double value = OracleFloat.toDouble(in, (int) pos, length);
        pos += length;
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            throw new SQLException("a JSON value holds " + value
                    + ", which JSON text has no spelling for", "22000");
        }
        out.append(length == 4 ? Float.toString((float) value) : Double.toString(value));
    }

    /** A date or a timestamp, as json_serialize writes it: ISO text in quotes. */
    private void moment(int length, StringBuilder out) {
        String text = OracleDate.toText(in, pos, length).replace(' ', 'T');
        pos += length;
        if (length >= OracleDate.DATE_LENGTH + 4) {
            // A timestamp carries its fraction to at least six places in
            // json_serialize - .500000, and .000000 for none - and to nine
            // where it needs them. A date has none.
            text = sixPlaces(text);
        }
        quoted(text, out);
    }

    /** "...T13:14:15.5+02:00" as "...T13:14:15.500000+02:00". */
    static String sixPlaces(String text) {
        int time = text.indexOf('T');
        int end = time + 9;                                // after HH:mm:ss
        int zone = end;
        while (zone < text.length() && text.charAt(zone) != '+' && text.charAt(zone) != '-'
                && text.charAt(zone) != 'Z') {
            zone++;
        }
        String fraction = zone > end ? text.substring(end + 1, zone) : "";
        StringBuilder padded = new StringBuilder(fraction);
        while (padded.length() < 6) {
            padded.append('0');
        }
        return text.substring(0, end) + "." + padded + text.substring(zone);
    }

    /** Binary as uppercase hex, the way json_serialize writes it. */
    private void binary(long length, StringBuilder out) {
        out.append('"');
        for (long i = 0; i < length; i++) {
            int value = in.get(ValueLayout.JAVA_BYTE, pos + i) & 0xff;
            out.append(Character.toUpperCase(Character.forDigit(value >>> 4, 16)));
            out.append(Character.toUpperCase(Character.forDigit(value & 0x0f, 16)));
        }
        out.append('"');
        pos += length;
    }

    private static void quoted(String text, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private String utf8(long at, int length) {
        check(at, length);
        return new String(in.asSlice(at, length).toArray(ValueLayout.JAVA_BYTE), // seclume-allow: user payload requested as text, not a secret
                StandardCharsets.UTF_8);
    }

    private void check(long at, long length) {
        if (at < start || at + length > end) {
            throw new IndexOutOfBoundsException("an OSON offset points at byte "
                    + (at - start) + " of a value of " + (end - start));
        }
    }

    private int u8() {
        check(pos, 1);
        return in.get(ValueLayout.JAVA_BYTE, pos++) & 0xff;
    }

    private int u16() {
        return (u8() << 8) | u8();
    }

    private long u32() {
        return ((long) u16() << 16) | u16();
    }
}
