package space.seclume.oracle.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

import space.seclume.internal.WireBuffer;
import space.seclume.internal.jdbc.ReadOnlyResultSet;
import space.seclume.oracle.net.TtcLob;
import space.seclume.oracle.net.OracleColumn;
import space.seclume.oracle.net.OracleFloat;
import space.seclume.oracle.net.OracleDate;
import space.seclume.oracle.net.OracleNumber;

/**
 * A {@code ResultSet} on top of an {@link OraResultBlock}.
 *
 * <p>Everything formal - the cursor, {@code wasNull}, the many methods that do
 * not apply to a forward-only result - lives in {@link ReadOnlyResultSet}. Only
 * the values are here, and with Oracle that means mostly one thing: numbers.
 *
 * <p>Oracle has a single numeric type, and it arrives in a format of its own -
 * base 100, with an exponent byte. {@link OracleNumber} turns it into a
 * {@code long} without a {@code String} on the way, which is the whole point:
 * {@code getLong} allocates nothing.
 */
public final class OraResultSet extends ReadOnlyResultSet implements space.seclume.Sensitive {

    private final OraResultBlock block;

    /** The statement that can bring the next block, or {@code null}. */
    private final OraStatement owner;

    @Override
    protected java.sql.Clob clobAt(int column) throws SQLException {
        return OraLob.clob(lobSession(), block.data(), block.offset(column));
    }

    @Override
    protected java.sql.Blob blobAt(int column) throws SQLException {
        return OraLob.blob(lobSession(), block.data(), block.offset(column));
    }

    @Override
    protected java.io.Reader readerAt(int column) throws SQLException {
        if (block.column(column).type() != OracleColumn.TYPE_CLOB) {
            return new java.io.StringReader(stringAt(column));
        }
        return clobAt(column).getCharacterStream();
    }

    @Override
    protected java.io.InputStream binaryStreamAt(int column) throws SQLException {
        if (!OracleColumn.isLob(block.column(column).type())
                || block.column(column).type() == OracleColumn.TYPE_JSON) {
            return new java.io.ByteArrayInputStream(bytesAt(column));
        }
        return blobAt(column).getBinaryStream();
    }

    private space.seclume.oracle.OracleSession lobSession() throws SQLException {
        if (owner == null) {
            throw new SQLException("this result has no statement to read the LOB with", "HY000");
        }
        return owner.connection.session();
    }

    /**
     * The contents of a CLOB, as text.
     *
     * <p>Oracle sends character LOBs in UTF-16, big-endian. The length is
     * not asked for: it came with the row, so the
     * whole value costs exactly one round trip however large it is.
     */
    private String clobText(int column) throws SQLException {
        try (WireBuffer value = fetchLob(column)) {
            int bytes = value.position();
            StringBuilder text = new StringBuilder(bytes / 2); // seclume-allow: user payload requested as text, not a secret
            for (int i = 0; i + 1 < bytes; i += 2) {
                text.append((char) (((value.getByte(i) & 0xff) << 8)
                        | (value.getByte(i + 1) & 0xff)));
            }
            return text.toString();
        }
    }

    /**
     * A {@code JSON} column as JSON text.
     *
     * <p>The locator's LOB holds OSON, and that is decoded here rather than
     * handed out: a caller without ojdbc's JSON classes - Hibernate, Jackson,
     * a plain {@code getString} - can do nothing with the binary tree.
     */
    private String jsonText(int column) throws SQLException {
        if (block.column(column).inline()) {
            // Brought in the row by the define - no round trip.
            return space.seclume.oracle.net.OracleJson.toText(block.data().segment(),
                    block.offset(column), block.length(column));
        }
        try (WireBuffer value = fetchLob(column)) {
            return space.seclume.oracle.net.OracleJson.toText(value.segment(), 0,
                    value.position());
        }
    }

    /** The contents of a LOB as bytes - for a BLOB, the value itself. */
    private byte[] lobBytes(int column) throws SQLException {
        try (WireBuffer value = fetchLob(column)) {
            int bytes = value.position();
            byte[] out = new byte[bytes]; // seclume-allow: user payload requested as bytes, not a secret
            for (int i = 0; i < bytes; i++) {
                out[i] = value.getByte(i);
            }
            return out;
        }
    }

    /**
     * The one round trip a LOB costs.
     *
     * <p>The row carried a locator, not a value; this turns it into the value.
     * An empty LOB comes back as no bytes at all, which is the same answer the
     * server gives for a read past the end - and rightly so: an empty LOB and
     * the end of a LOB are the same thing seen from the offset.
     */
    private WireBuffer fetchLob(int column) throws SQLException {
        long length = block.lobLength(column);
        if (length == 0) {
            return new WireBuffer(16);                 // empty, and the server need not say so
        }
        WireBuffer value = new WireBuffer(
                length > 0 ? (int) Math.min(length * 2, 1 << 16) : 16 * 1024);
        if (owner == null) {
            value.close();
            throw new SQLException("this result has no statement to read the LOB with", "HY000");
        }
        // A column's locator is usually a persistent one, 112 bytes; a JSON
        // column's is a temporary one of 38. The row said which.
        int locator = block.length(column);
        owner.connection.session().readLob(block.data(), block.offset(column),
                locator > 0 ? locator : TtcLob.LOCATOR_LENGTH, 1, TtcLob.ALL, value);
        return value;
    }

    /**
     * Asks the statement for the next block.
     *
     * <p>Only does anything when a fetch size is set and the cursor still has
     * rows; otherwise the whole result is here already and this says so.
     */
    @Override
    protected boolean fetchMore() throws SQLException {
        return owner != null && owner.fetchNextBlock();
    }

    OraResultSet(OraResultBlock block, Statement statement) {
        super(statement);
        this.block = block;
        this.owner = statement instanceof OraStatement ora ? ora : null;
    }

    @Override
    protected int rowCount() {
        return block.rowCount();
    }

    @Override
    protected int columnCount() {
        return block.columnCount();
    }

    @Override
    protected void moveTo(int row) {
        block.select(row);
    }

    @Override
    protected boolean isNullAt(int column) {
        return block.isNull(column);
    }

    @Override
    protected String stringAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        int at = block.offset(column);
        int length = block.length(column);
        if (description.type() == OracleColumn.TYPE_CLOB) {
            return clobText(column);
        }
        if (description.type() == OracleColumn.TYPE_OBJECT) {
            if (!description.isXml()) {
                throw new SQLException("column " + (column + 1) + " is an object of type "
                        + description.objectType() + ", which this driver does not read - "
                        + "select its attributes instead", "0A000");
            }
            return space.seclume.oracle.net.OracleXml.fromImage(block.data().segment(), at,
                    length);
        }
        if (description.type() == OracleColumn.TYPE_ROWID) {
            return space.seclume.oracle.net.OracleRowid.toText(block.data().segment(), at,
                    length);
        }
        if (description.type() == OracleColumn.TYPE_BLOB) {
            throw new SQLException("a BLOB is not text", "22005");
        }
        if (description.type() == OracleColumn.TYPE_JSON) {
            return jsonText(column);
        }
        if (description.type() == OracleColumn.TYPE_VECTOR) {
            if (description.inline()) {
                return space.seclume.oracle.net.OracleVector.toText(block.data().segment(),
                        at, length);
            }
            try (WireBuffer value = fetchLob(column)) {
                return space.seclume.oracle.net.OracleVector.toText(value.segment(), 0,
                        value.position());
            }
        }
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            return OracleNumber.toText(block.data().segment(), at, length);
        }
        if (OracleFloat.isBinaryFloat(description.type())) {
            double value = OracleFloat.toDouble(block.data().segment(), at, length);
            return description.type() == OracleColumn.TYPE_BINARY_FLOAT
                    ? Float.toString((float) value) : Double.toString(value);
        }
        if (description.type() == OracleColumn.TYPE_BOOLEAN) {
            // "true", as ojdbc writes it - and as the server does in to_char.
            return length > 0 && block.data().getByte(at) != 0 ? "true" : "false";
        }
        if (description.type() == OracleColumn.TYPE_UROWID) {
            return space.seclume.oracle.net.OracleRowid.fromUrowid(block.data().segment(), at,
                    length);
        }
        if (description.type() == OracleColumn.TYPE_INTERVAL_YM) {
            return OracleDate.intervalYearToMonth(block.data().segment(), at);
        }
        if (description.type() == OracleColumn.TYPE_INTERVAL_DS) {
            return OracleDate.intervalDayToSecond(block.data().segment(), at);
        }
        if (description.type() == OracleColumn.TYPE_BFILE) {
            // A locator for a file on the server, which this driver does not
            // open. ojdbc's getString answers null as well; before, the
            // locator was not even framed and broke every column after it.
            return null;
        }
        if (description.type() == OracleColumn.TYPE_TIMESTAMP_ZONE) {
            java.time.ZonedDateTime value = zonedAt(column);
            return ojdbcText(value.toLocalDateTime()) + " " + zoneText(column, value);
        }
        if (description.type() == OracleColumn.TYPE_TIMESTAMP_LOCAL) {
            return ojdbcText(localAt(column)) + " " + lobSession().zones()[0].getId();
        }
        if (OracleDate.isDate(description.type())) {
            return OracleDate.toText(block.data().segment(), at, length);
        }
        // RAW as hex, not as characters. Running the bytes of a raw(32)
        // through the text decoder produced whatever they happened to look
        // like - for 00 01 02 FF 80 a string of control and replacement
        // characters, which represents nothing and loses the value. ojdbc
        // answers with uppercase hex.
        if (description.type() == OracleColumn.TYPE_RAW
                || description.type() == OracleColumn.TYPE_LONG_RAW) {
            return hex(at, length);
        }
        // The national types arrive in AL16UTF16, not in the database
        // character set. Decoding those bytes as UTF-8 turned "gruess" with
        // umlauts into a string of NULs and replacement characters - every
        // value of every NVARCHAR2 column, silently. The column has said
        // which character set it is in all along; nothing asked it.
        return description.charset() == AL16UTF16 ? utf16(at, length) : utf8(at, length);
    }

    /**
     * A {@code TIMESTAMP WITH TIME ZONE} as the point in time it names, in
     * its own zone.
     *
     * <p>The fields on the wire are UTC and the zone stands beside them. This
     * used to print the UTC fields with the offset behind them - a value
     * written as 13:14+02:00 read back as 11:14+02:00, two hours early, and
     * getTimestamp followed it. A region arrives as a number and was printed
     * as an offset of "+113:156", which nothing could read.
     */
    private java.time.ZonedDateTime zonedAt(int column) throws SQLException {
        java.lang.foreign.MemorySegment in = block.data().segment();
        int at = block.offset(column);
        int length = block.length(column);
        java.time.ZoneId zone;
        if (OracleDate.isRegion(in, at, length)) {
            String name = lobSession().regionName(OracleDate.regionId(in, at));
            try {
                zone = java.time.ZoneId.of(name);
            } catch (RuntimeException unknown) {
                throw new SQLException("time zone region " + OracleDate.regionId(in, at)
                        + " (" + name + ") is not one this JVM knows", "22009", unknown);
            }
        } else {
            zone = java.time.ZoneOffset.ofTotalSeconds(OracleDate.zoneMinutes(in, at) * 60);
        }
        return OracleDate.fields(in, at, length).atZone(java.time.ZoneOffset.UTC)
                .withZoneSameInstant(zone);
    }

    /** The zone as ojdbc writes it: the region's name, or "+2:00". */
    private String zoneText(int column, java.time.ZonedDateTime value) {
        if (!(value.getZone() instanceof java.time.ZoneOffset offset)) {
            return value.getZone().getId();
        }
        int minutes = offset.getTotalSeconds() / 60;
        return (minutes < 0 ? "-" : "+") + Math.abs(minutes) / 60 + ":"
                + String.format("%02d", Math.abs(minutes) % 60);
    }

    /**
     * A {@code TIMESTAMP WITH LOCAL TIME ZONE} in the session's zone. It
     * travels in the database's, and was handed out as it travelled.
     */
    private java.time.LocalDateTime localAt(int column) throws SQLException {
        java.time.ZoneId[] zones = lobSession().zones();
        return OracleDate.fields(block.data().segment(), block.offset(column),
                        block.length(column))
                .atZone(zones[1]).withZoneSameInstant(zones[0]).toLocalDateTime();
    }

    /**
     * "2024-02-29 13:14:15.123456", and ".0" for no fraction - Timestamp's
     * form, written out: going through a Timestamp would move a time that
     * falls into a daylight-saving gap of this JVM's zone.
     */
    private static String ojdbcText(java.time.LocalDateTime value) {
        String fraction = String.format("%09d", value.getNano()).replaceAll("0+$", "");
        return String.format("%04d-%02d-%02d %02d:%02d:%02d.%s", value.getYear(),
                value.getMonthValue(), value.getDayOfMonth(), value.getHour(),
                value.getMinute(), value.getSecond(), fraction.isEmpty() ? "0" : fraction);
    }

    @Override
    protected Object temporalAt(int column) throws SQLException {
        return switch (block.column(column).type()) {
            case OracleColumn.TYPE_TIMESTAMP_ZONE -> zonedAt(column).toOffsetDateTime();
            case OracleColumn.TYPE_TIMESTAMP_LOCAL -> localAt(column);
            default -> null;
        };
    }

    /** Uppercase hex, the way Oracle and ojdbc render a raw. */
    private String hex(int at, int length) {
        StringBuilder text = new StringBuilder(length * 2); // seclume-allow: user payload requested as text, not a secret
        for (int i = 0; i < length; i++) {
            int value = block.data().getByte(at + i) & 0xff;
            text.append(Character.toUpperCase(Character.forDigit(value >>> 4, 16)));
            text.append(Character.toUpperCase(Character.forDigit(value & 0x0f, 16)));
        }
        return text.toString();
    }

    /** Oracle's national character set: UTF-16, big-endian, no BOM. */
    private static final int AL16UTF16 = 2000;

    /**
     * The bytes of a national text column, decoded as UTF-16BE.
     *
     * <p>Surrogate pairs pass through as the two chars they already are -
     * Java strings are UTF-16 too, so a pair needs no assembling, only
     * copying. An odd trailing byte is dropped rather than throwing, for the
     * same reason {@link #utf8} does not throw: a result set is no place to
     * fail over one bad byte.
     */
    private String utf16(int at, int length) {
        StringBuilder text = new StringBuilder(length / 2); // seclume-allow: user payload requested as text, not a secret
        for (int i = 0; i + 1 < length; i += 2) {
            int high = block.data().getByte(at + i) & 0xff;
            int low = block.data().getByte(at + i + 1) & 0xff;
            text.append((char) ((high << 8) | low));
        }
        return text.toString();
    }

    /**
     * The bytes of a text column, decoded as UTF-8.
     *
     * <p>The driver logs in with AL32UTF8 and the server answers in it, so a
     * character outside ASCII arrives as two bytes or more. Reading them one
     * byte per character - which is what this did - turns "Grüße" into
     * "GrÃ¼ÃŸe", and only for the values that have such a character in them.
     *
     * <p>Written out rather than handed to {@code new String(bytes, UTF_8)}:
     * that would need the bytes in a heap array first, which is the one
     * thing this project does not do. A malformed sequence becomes the
     * replacement character rather than throwing - a result set is no place
     * to fail over one bad byte.
     */
    private String utf8(int at, int length) {
        StringBuilder text = new StringBuilder(length); // seclume-allow: user payload requested as text, not a secret
        int i = 0;
        while (i < length) {
            int first = block.data().getByte(at + i) & 0xff;
            i++;
            if (first < 0x80) {
                text.append((char) first);
                continue;
            }
            int following = first >= 0xf0 ? 3 : first >= 0xe0 ? 2 : first >= 0xc0 ? 1 : -1;
            if (following < 0 || i + following > length) {
                text.append('�');
                continue;
            }
            int point = first & (0x3f >> following);
            for (int k = 0; k < following; k++) {
                int next = block.data().getByte(at + i + k) & 0xff;
                if ((next & 0xc0) != 0x80) {
                    point = -1;
                    break;
                }
                point = (point << 6) | (next & 0x3f);
            }
            if (point < 0) {
                text.append('�');
                continue;
            }
            i += following;
            text.appendCodePoint(point);
        }
        return text.toString();
    }

    @Override
    protected long longAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            return OracleNumber.toLong(block.data().segment(), block.offset(column),
                    block.length(column));
        }
        if (OracleFloat.isBinaryFloat(description.type())) {
            return (long) OracleFloat.toDouble(block.data().segment(), block.offset(column),
                    block.length(column));
        }
        if (description.type() == OracleColumn.TYPE_BOOLEAN) {
            return block.length(column) > 0
                    && block.data().getByte(block.offset(column)) != 0 ? 1 : 0;
        }
        try {
            return Long.parseLong(stringAt(column).trim());
        } catch (NumberFormatException e) {
            throw new SQLException("column " + (column + 1) + " is not an integer: "
                    + stringAt(column), "22018", e);
        }
    }

    @Override
    protected double doubleAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            return OracleNumber.toDouble(block.data().segment(), block.offset(column),
                    block.length(column));
        }
        if (OracleFloat.isBinaryFloat(description.type())) {
            return OracleFloat.toDouble(block.data().segment(), block.offset(column),
                    block.length(column));
        }
        try {
            return Double.parseDouble(stringAt(column));
        } catch (NumberFormatException e) {
            throw new SQLException("column " + (column + 1) + " is not a number: "
                    + stringAt(column), "22018", e);
        }
    }

    @Override
    protected byte[] bytesAt(int column) throws SQLException {
        if (block.column(column).type() == OracleColumn.TYPE_JSON) {
            // The text in UTF-8, as for a JSON column on the other three -
            // not the OSON tree, which nothing outside ojdbc can read.
            return jsonText(column).getBytes(java.nio.charset.StandardCharsets.UTF_8); // seclume-allow: user payload requested as bytes, not a secret
        }
        if (OracleColumn.isLob(block.column(column).type())) {
            return lobBytes(column);
        }
        int at = block.offset(column);
        int length = block.length(column);
        byte[] out = new byte[length]; // seclume-allow: user payload requested as bytes, not a secret
        for (int i = 0; i < length; i++) {
            out[i] = block.data().getByte(at + i);
        }
        return out;
    }

    /**
     * Oracle has no boolean type before 23c, and this driver does not use the
     * new one yet: a truth value is a number or a letter, and both are
     * accepted the way every other Oracle client accepts them.
     */
    @Override
    protected boolean booleanAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            return longAt(column) != 0;
        }
        String text = stringAt(column).trim();
        if (text.isEmpty()) {
            return false;
        }
        char first = text.charAt(0);
        return first == 'Y' || first == 'y' || first == 'T' || first == 't' || first == '1';
    }

    /** An {@code XMLType} column as {@link java.sql.SQLXML}. */
    @Override
    protected java.sql.SQLXML sqlXmlAt(int column) throws SQLException {
        if (!block.column(column).isXml()) {
            throw new SQLException("column " + (column + 1) + " is not XMLType - read it with "
                    + "getString", "42804");
        }
        return new space.seclume.internal.jdbc.XmlValue(stringAt(column));
    }

    /** A {@code ROWID} column as {@link java.sql.RowId} - its printed form. */
    @Override
    protected java.sql.RowId rowIdAt(int column) throws SQLException {
        int type = block.column(column).type();
        if (type != OracleColumn.TYPE_ROWID && type != OracleColumn.TYPE_UROWID) {
            throw new SQLException("column " + (column + 1) + " is not a ROWID - select "
                    + "rowid to get one", "42804");
        }
        return new space.seclume.internal.jdbc.OpaqueRowId(stringAt(column));
    }

    @Override
    protected Object objectAt(int column) throws SQLException {
        OracleColumn description = block.column(column);
        if (description.type() == OracleColumn.TYPE_ROWID
                || description.type() == OracleColumn.TYPE_UROWID) {
            return rowIdAt(column);
        }
        if (description.isXml()) {
            return sqlXmlAt(column);
        }
        if (description.type() == OracleColumn.TYPE_NUMBER) {
            // BigDecimal for every NUMBER, as ojdbc hands it out: code that
            // casts getObject - Spring's queryForList, a row mapper - was
            // written against that and does not expect a Long for NUMBER(10).
            return new java.math.BigDecimal(stringAt(column));
        }
        if (description.type() == OracleColumn.TYPE_TIMESTAMP_ZONE) {
            return zonedAt(column).toOffsetDateTime();
        }
        if (description.type() == OracleColumn.TYPE_TIMESTAMP_LOCAL) {
            return java.sql.Timestamp.valueOf(localAt(column));
        }
        if (OracleDate.isDate(description.type())) {
            return java.sql.Timestamp.valueOf(stringAt(column));
        }
        // A raw is bytes, and getColumnClassName promises [B. Returning the
        // hex string instead made the metadata a lie and handed callers
        // something they would have to parse back.
        if (description.type() == OracleColumn.TYPE_RAW
                || description.type() == OracleColumn.TYPE_LONG_RAW) {
            return getBytes(column + 1);
        }
        if (description.type() == OracleColumn.TYPE_BINARY_FLOAT) {
            return Float.valueOf((float) getDouble(column + 1));
        }
        if (description.type() == OracleColumn.TYPE_BINARY_DOUBLE) {
            return Double.valueOf(getDouble(column + 1));
        }
        if (description.type() == OracleColumn.TYPE_BOOLEAN) {
            return Boolean.valueOf(getBoolean(column + 1));
        }
        return stringAt(column);
    }

    @Override
    protected int columnIndexOf(String label) {
        for (int i = 0; i < block.columnCount(); i++) {
            if (block.column(i).name().equalsIgnoreCase(label)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    protected ResultSetMetaData metaData() {
        return new OraResultSetMetaData(block.columns());
    }

    /**
     * Nothing to free here: the block belongs to the statement and the next
     * execution reuses it. Closing it would pull the memory out from under the
     * statement.
     */
    @Override
    protected void release() {
    }

    // ---- the native window, for space.seclume.Sensitive ------------------

    @Override
    protected java.lang.foreign.MemorySegment rawSegmentAt(int column) {
        return block.data().segment();
    }

    @Override
    protected long rawOffsetAt(int column) {
        return block.offset(column);
    }

    @Override
    protected int rawLengthAt(int column) {
        return block.length(column);
    }

    @Override
    public int readInto(int columnIndex, java.lang.foreign.MemorySegment target)
            throws java.sql.SQLException {
        return copyRaw(columnIndex, target);
    }

    @Override
    public int length(int columnIndex) throws java.sql.SQLException {
        return rawLength(columnIndex);
    }

}
