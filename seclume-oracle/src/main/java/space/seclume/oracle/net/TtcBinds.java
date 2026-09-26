package space.seclume.oracle.net;

import java.math.BigDecimal;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * The bind variables of a statement.
 *
 * <p>Oracle sends them in two parts, and they sit far apart in the message:
 * first a <b>description</b> per variable - type, buffer size, character set -
 * behind the statement text, and then the <b>values</b>, introduced by a
 * {@code ROW_DATA} byte. Both are written here so that the two lists cannot
 * drift apart.
 *
 * <p>The shapes are derived from {@code python-oracledb} 4.0.2 (UPL-1.0 or
 * Apache-2.0; see {@code PROVENANCE.md}) and held by byte-level unit tests
 * ({@code insert into ... values (:1, :2)} with a number and a string).
 * A number describes itself with a buffer of 22 bytes and
 * no character set, a string with four bytes per character and character set
 * 873.
 */
public final class TtcBinds {

    /** How many bytes a NUMBER takes at most. */
    private static final int NUMBER_SIZE = 22;
    /** How many bytes a DATE takes. */
    private static final int DATE_SIZE = 7;
    /**
     * How many bytes a TIMESTAMP takes: the seven of a DATE and four more for
     * the fraction of a second.
     *
     * <p>Sending a point in time as a DATE is what this driver did, and it
     * costs the fraction silently - a row written at 11:29:16.153 comes back
     * as 11:29:16, and nothing anywhere says so. Hibernate's
     * {@code @LastModifiedDate} then compares two timestamps that differ by
     * less than a second and finds them equal. So anything carrying a time of
     * day goes as a TIMESTAMP; a bare date still goes as a DATE, which is
     * what it is.
     */
    private static final int TIMESTAMP_SIZE = 11;
    /**
     * A TIMESTAMP WITH TIME ZONE: the eleven of a TIMESTAMP and two more for
     * the offset - the hour shifted by 20 and the minute by 60, so that a
     * negative offset has no negative byte.
     */
    private static final int TIMESTAMP_ZONE_SIZE = 13;
    /** Oracle's offset for the hours of a time zone. */
    private static final int ZONE_HOUR_BIAS = 20;
    /** And for its minutes. */
    private static final int ZONE_MINUTE_BIAS = 60;
    /** Bytes per character the server is told to expect. */
    private static final int BYTES_PER_CHARACTER = 4;
    /** AL32UTF8, the character set this driver talks. */
    private static final int CHARSET = 873;
    /** The character set form of a normal string. */
    private static final int CSFRM_IMPLICIT = 1;
    /** A buffer size for a bind whose value is null. */
    private static final int NULL_SIZE = 1;
    /** Oracle's offset for the century and the year in a DATE. */
    private static final int YEAR_BIAS = 100;
    /** Up to this length a value carries a single length byte. */
    private static final int SHORT_LENGTH = 252;
    /** The length byte that says "chunks follow". */
    private static final int CHUNKED = 0xfe;
    /** How much goes into one chunk. */
    private static final int CHUNK_SIZE = 32767;

    /**
     * Beyond this buffer size the server takes a bind for a {@code LONG}.
     *
     * <p>The same number as a chunk: 32767 bytes is the most a
     * {@code VARCHAR2} or {@code RAW} bind can be, and a string or a byte
     * array described any wider is handled as {@code LONG} or
     * {@code LONG RAW} - which is how a value of 700 000 characters reaches
     * a CLOB column at all.
     */
    private static final long LONGEST_PLAIN = CHUNK_SIZE;

    /** The values this list owns. */
    private final List<Object> own = new ArrayList<>();
    /**
     * What is bound: {@link #own}, or during a batch a view onto the row
     * being written - see {@link #setAll}.
     */
    private List<Object> values = own;

    /** Back to the owned list before anything changes it. */
    private List<Object> owned() {
        if (values != own) {
            own.clear();
            own.addAll(values);
            values = own;
        }
        return own;
    }

    /**
     * Which variables were described as long ones, by the last
     * {@link #putDescriptors} - their values go last. See {@link #putValues}.
     */
    private boolean[] described;

    /**
     * A LOB handed over as a locator rather than as a value.
     *
     * <p>The descriptor and the value are covered for a CLOB and for a
     * BLOB; they differ only in the type and in the character set, which a BLOB
     * leaves at zero. The value carries the same „two bytes plus the locator"
     * shape that the LOB calls use.
     *
     * @param buffer where the locator lies
     * @param at     its first byte
     * @param length how long it is — 38 for a temporary LOB, 112 for a
     *               persistent one; never assumed
     */
    public record Locator(WireBuffer buffer, int at, int length, boolean character) {
    }

    /**
     * The buffer size the server is told for a locator: 112, whatever the
     * locator itself is long. The same for both kinds.
     */
    private static final long LOCATOR_BUFFER = 112;

    /** The same in both kinds of locator bind; not decoded further. */
    private static final long LOCATOR_CONTINUATION = 0x02000000L;

    /** A fresh, empty list of bind variables. */
    public TtcBinds() {
    }

    /** The whole row of a batch at once - what a batch binds for every row, twice. */
    public void setAll(Object[] row) {
        // A view, not a copy: every row of a batch is bound twice - measured,
        // then written - and copying it into the list each time was the
        // largest cost left in encoding one.
        values = java.util.Arrays.asList(row);
    }

    /** Sets a value; the index is the JDBC one and starts at one. */
    public void set(int index, Object value) throws SQLException {
        if (index < 1) {
            throw new SQLException("a parameter index starts at 1, not " + index);
        }
        while (values.size() < index) {
            owned().add(null);
        }
        owned().set(index - 1, value);
    }


    /**
     * A bind the <b>server</b> fills - the {@code into} of a DML returning.
     *
     * <p>Such a bind is described like any other, with the same flag byte,
     * and simply carries <b>no value</b> in
     * the row data. The server knows it is an output from the statement text.
     * The answer then arrives as a {@code ROW_DATA} message in front of
     * everything else - see {@code TtcResult#returned}.
     */
    public void addOutput() {
        owned().add(new Output(OracleColumn.TYPE_NUMBER, false));
    }

    /**
     * Marks a chosen place as one the server writes into, with the type it
     * should write there.
     *
     * <p>{@link #addOutput()} appends, which is all a {@code returning into}
     * needs - its binds go at the end. A procedure call cannot: its outputs
     * sit wherever the caller wrote them, and each has a type of its own. A
     * {@code VARCHAR2} output described as a NUMBER comes back as bytes that
     * decode into nonsense rather than into an error.
     *
     * @param type one of {@link OracleColumn}'s type numbers
     */
    public void setOutput(int index, int type) throws SQLException {
        set(index, new Output(type, true));
    }

    /** Whether this list has an output bind in it. */
    public boolean hasOutput() {
        for (Object value : values) {
            if (value instanceof Output) {
                return true;
            }
        }
        return false;
    }

    /**
     * A place the server writes into.
     *
     * <p>{@code placeholder} is the awkward part, and the two cases genuinely
     * differ. A {@code returning into} bind carries <b>nothing</b> in the row
     * data. A bind of a PL/SQL call carries a <b>length of zero</b>: the
     * answer to {@code begin p(:1, :2); end;} ends in
     * {@code 07 02 C1 16 00}, where the {@code 07} opens the values, the
     * {@code 02 C1 16} is the input 21 and the last {@code 00} is the output's
     * empty value. Leaving it out makes the message one byte short, and Oracle
     * answers a short message by waiting for the rest - the session sits in
     * {@code SQL*Net more data from client} and the client waits for an answer
     * that will never come.
     */
    private record Output(int type, boolean placeholder) {
    }

    /** The value at a JDBC index, or {@code null}. */
    public Object get(int index) {
        return index >= 1 && index <= values.size() ? values.get(index - 1) : null;
    }

    public int count() {
        return values.size();
    }

    public void clear() {
        values = own;
        own.clear();
    }

    /**
     * The description of every variable, in order.
     *
     * <p>Thirteen fields each, and the last four are zero for everything this
     * driver sends. The character set is the only one that depends on the
     * value: a number has none, a string has 873.
     */
    public void putDescriptors(WireBuffer out) throws SQLException {
        putDescriptors(out, null);
    }

    /**
     * The same, with the buffer sizes decided outside.
     *
     * <p>A batch describes its variables <b>once</b> and then sends many sets
     * of values. The description has to fit the widest of them: a text column
     * whose first row holds three characters and whose tenth holds forty would
     * otherwise be described three characters wide. The caller walks the rows
     * first and passes the maximum per column.
     *
     * @param sizes the buffer size per variable, or {@code null} for this row
     */
    public void putDescriptors(WireBuffer out, long[] sizes) throws SQLException {
        messageRules = null;                           // a new message, a fresh look
        described = new boolean[values.size()];
        for (int index = 0; index < values.size(); index++) {
            Object value = values.get(index);
            int type = value instanceof Output output ? output.type() : typeOf(value);
            long size = value instanceof Output
                    ? outputBufferSize(type)
                    : (sizes == null ? bufferSizeOf(value, type) : sizes[index]);
            described[index] = !(value instanceof Output) && size > LONGEST_PLAIN;
            out.putByte((byte) type);
            out.putByte((byte) 1);                     // flags, always one here
            out.putByte((byte) 0);                     // precision
            out.putByte((byte) 0);                     // scale
            TtcParameters.putNumber(out, size);
            TtcParameters.putNumber(out, 0);           // largest number of array elements
            TtcParameters.putNumber(out, value instanceof Locator
                    ? LOCATOR_CONTINUATION : 0);       // continuation flags
            out.putByte((byte) 0);                     // object id
            TtcParameters.putNumber(out, 0);           // version
            boolean text = type == OracleColumn.TYPE_VARCHAR
                    || (value instanceof Locator lob && lob.character());
            TtcParameters.putNumber(out, text ? CHARSET : 0);
            out.putByte((byte) (text ? CSFRM_IMPLICIT : 0));
            TtcParameters.putNumber(out, 0);           // largest character count
            TtcParameters.putNumber(out, 0);           // oaccolid
        }
    }

    /**
     * The values, introduced by the {@code ROW_DATA} byte.
     *
     * <p>A null is a length of zero and nothing else - the same shape a null
     * column has in a row coming back.
     *
     * <p>The values of long variables - described wider than
     * {@link #LONGEST_PLAIN} - come <b>after all the others</b>, in their own
     * order; the descriptions stay where they are. The server reads a
     * {@code LONG} last whatever its place in the statement. Written in place,
     * the value behind it is read as the long one's, and the answer is
     * ORA-01461 naming the wrong position. Hibernate's insert of an entity
     * with a large {@code @Lob String} and a {@code Blob} column after it did
     * exactly that; python-oracledb writes long values last as well.
     */
    public void putValues(WireBuffer out) throws SQLException {
        out.putByte((byte) TtcMessage.TYPE_ROW_DATA);
        boolean anyLong = false;
        for (int index = 0; index < values.size(); index++) {
            Object value = values.get(index);
            if (isLong(index)) {
                anyLong = true;
                continue;
            }
            if (value instanceof Output output) {
                if (output.type() == OracleColumn.TYPE_CURSOR) {
                    // A cursor slot is not an empty value. It carries the
                    // number of the cursor the client is offering - zero,
                    // meaning "open one" - and that number is one byte long,
                    // so the pair is a length of 1 and the zero itself.
                    //
                    // Sending the empty value that every other output uses
                    // costs one byte, and the consequence is not an error:
                    // the server reads the following bind's description one
                    // byte out of step and then waits for the rest of a
                    // message that has already been sent. The call hangs.
                    out.putByte((byte) 1);
                    out.putByte((byte) 0);
                } else if (output.placeholder()) {
                    out.putByte((byte) 0);    // an empty value - see Output
                }
                continue;
            }
            putValue(out, value);
        }
        if (anyLong) {
            for (int index = 0; index < values.size(); index++) {
                if (isLong(index)) {
                    putValue(out, values.get(index));
                }
            }
        }
    }

    private boolean isLong(int index) {
        return described != null && index < described.length && described[index];
    }

    /**
     * How much room the server is given to write an output into.
     *
     * <p>A number and a date have a known width; text does not, and the
     * caller's registration says only the type. 4000 bytes is what a
     * {@code VARCHAR2} bind can hold, so it is what gets asked for - less
     * would truncate a value nobody could have known was longer.
     */
    private static long outputBufferSize(int type) {
        if (type == OracleColumn.TYPE_CURSOR) {
            // One byte, and it matters that it is not zero: with a size of
            // zero the server answers ORA-06502, a PL/SQL conversion error,
            // as though the parameter had been given a value of the wrong
            // type. Nothing is written into that byte - what comes back is
            // the cursor's description and its number, not a value.
            return 1;
        }
        if (type == OracleColumn.TYPE_VARCHAR) {
            return 4000L * BYTES_PER_CHARACTER;
        }
        if (type == OracleColumn.TYPE_DATE) {
            return DATE_SIZE;
        }
        if (type == OracleColumn.TYPE_TIMESTAMP) {
            return TIMESTAMP_SIZE;
        }
        if (type == OracleColumn.TYPE_TIMESTAMP_ZONE) {
            return TIMESTAMP_ZONE_SIZE;
        }
        return NUMBER_SIZE;
    }

    private void putValue(WireBuffer out, Object value) throws SQLException {
        switch (value) {
            case null -> out.putByte((byte) 0);
            case Boolean flag -> OracleNumber.encode(out, flag ? 1 : 0);
            case Byte number -> OracleNumber.encode(out, number.longValue());
            case Short number -> OracleNumber.encode(out, number.longValue());
            case Integer number -> OracleNumber.encode(out, number.longValue());
            case Long number -> OracleNumber.encode(out, number);
            case Float number -> OracleNumber.encodeText(out,
                    BigDecimal.valueOf(number.doubleValue()).toPlainString());
            case Double number -> OracleNumber.encodeText(out,
                    BigDecimal.valueOf(number).toPlainString());
            case BigDecimal number -> {
                if (number.unscaledValue().bitLength() < 63) {
                    OracleNumber.encodeScaled(out, number.unscaledValue().longValue(),
                            number.scale());
                } else {
                    OracleNumber.encodeText(out, number.toPlainString());
                }
            }
            case Locator lob -> putLocator(out, lob);
            case space.seclume.internal.jdbc.NativeValue nativeValue ->
                    putNative(out, nativeValue);
            case String text -> putText(out, text);
            case byte[] bytes -> putBytes(out, bytes);
            case LocalDate date -> putDate(out, date.atStartOfDay());
            // Oracle has no type for a time of day - Hibernate maps one to a
            // timestamp, and the date part is the epoch, as java.sql.Time
            // itself uses it.
            case LocalTime time -> putTimestamp(out, time.atDate(java.time.LocalDate.EPOCH));
            case java.sql.Time time -> putTimestamp(out,
                    time.toLocalTime().atDate(java.time.LocalDate.EPOCH));
            case LocalDateTime stamp -> putTimestamp(out, stamp);
            case java.sql.Date date -> putDate(out, date.toLocalDate().atStartOfDay());
            case java.sql.Timestamp stamp -> putTimestamp(out, localFields(stamp, messageRules()));
            case java.time.OffsetDateTime stamp -> putZonedTimestamp(out, stamp);
            case java.time.Instant instant -> putZonedTimestamp(out,
                    instant.atOffset(java.time.ZoneOffset.UTC));
            case java.util.UUID id -> putUuid(out, id);
            default -> throw new SQLException("seclume cannot send a "
                    + value.getClass().getName() + " to Oracle as a bind variable");
        }
    }

    /**
     * How much room this row would need per variable - for a batch that has
     * to describe them all with one size.
     */
    public void measure(long[] sizes) throws SQLException {
        for (int index = 0; index < values.size() && index < sizes.length; index++) {
            Object value = values.get(index);
            sizes[index] = Math.max(sizes[index], bufferSizeOf(value, typeOf(value)));
        }
    }

    /** The type byte the server is told about. */
    private static int typeOf(Object value) throws SQLException {
        return switch (value) {
            case null -> OracleColumn.TYPE_VARCHAR;
            case Boolean ignored -> OracleColumn.TYPE_NUMBER;
            case Byte ignored -> OracleColumn.TYPE_NUMBER;
            case Short ignored -> OracleColumn.TYPE_NUMBER;
            case Integer ignored -> OracleColumn.TYPE_NUMBER;
            case Long ignored -> OracleColumn.TYPE_NUMBER;
            case Float ignored -> OracleColumn.TYPE_NUMBER;
            case Double ignored -> OracleColumn.TYPE_NUMBER;
            case BigDecimal ignored -> OracleColumn.TYPE_NUMBER;
            case Locator lob -> lob.character()
                    ? OracleColumn.TYPE_CLOB : OracleColumn.TYPE_BLOB;
            case space.seclume.internal.jdbc.NativeValue ignored -> OracleColumn.TYPE_VARCHAR;
            case String ignored -> OracleColumn.TYPE_VARCHAR;
            case byte[] ignored -> OracleColumn.TYPE_RAW;
            case LocalDate ignored -> OracleColumn.TYPE_DATE;
            case LocalTime ignored -> OracleColumn.TYPE_TIMESTAMP;
            case java.sql.Time ignored -> OracleColumn.TYPE_TIMESTAMP;
            case LocalDateTime ignored -> OracleColumn.TYPE_TIMESTAMP;
            case java.sql.Date ignored -> OracleColumn.TYPE_DATE;
            case java.sql.Timestamp ignored -> OracleColumn.TYPE_TIMESTAMP;
            case java.time.OffsetDateTime ignored -> OracleColumn.TYPE_TIMESTAMP_ZONE;
            case java.time.Instant ignored -> OracleColumn.TYPE_TIMESTAMP_ZONE;
            case java.util.UUID ignored -> OracleColumn.TYPE_RAW;
            default -> throw new SQLException("seclume cannot send a "
                    + value.getClass().getName() + " to Oracle as a bind variable");
        };
    }

    /**
     * How much room the server should keep.
     *
     * <p>For a string that is four bytes per character, not the length of this
     * one: the same statement runs again with other values, and a buffer cut
     * to the first value would have to be renegotiated every time.
     */
    private static long bufferSizeOf(Object value, int type) {
        if (value instanceof Locator) {
            return LOCATOR_BUFFER;
        }
        if (value instanceof space.seclume.internal.jdbc.NativeValue nativeValue) {
            // Before the switch below, which reaches its default and casts to
            // String. The bytes are already bytes - see SensitiveParameters.
            return Math.max(nativeValue.length(), 1);
        }
        return switch (type) {
            case OracleColumn.TYPE_NUMBER -> NUMBER_SIZE;
            case OracleColumn.TYPE_DATE -> DATE_SIZE;
            case OracleColumn.TYPE_TIMESTAMP -> TIMESTAMP_SIZE;
            case OracleColumn.TYPE_TIMESTAMP_ZONE -> TIMESTAMP_ZONE_SIZE;
            case OracleColumn.TYPE_RAW -> Math.max(((byte[]) value).length, 1);
            default -> value == null ? NULL_SIZE
                    : Math.max(((String) value).length() * BYTES_PER_CHARACTER, 1);
        };
    }

    /**
     * A locator as a bind value.
     *
     * <p>The size as a number, the same size as a single byte, then
     * two bytes naming the locator's own length, then the locator. The two
     * extra bytes are the same ones the LOB calls put in front of a locator.
     */
    private static void putLocator(WireBuffer out, Locator lob) {
        int descriptor = lob.length() + 2;
        TtcParameters.putNumber(out, descriptor);
        out.putByte((byte) descriptor);
        out.putByte((byte) 0);
        out.putByte((byte) lob.length());
        out.putBytes(lob.buffer().segment(), lob.at(), lob.length());
    }

    private static void putText(WireBuffer out, String text) {
        int start = out.position();
        out.putByte((byte) 0);                         // room for the length
        out.putText(text);
        int length = out.position() - start - 1;
        if (length <= SHORT_LENGTH) {
            out.putByteAt(start, (byte) length);
            return;
        }
        // Too long for a single length byte: the bytes have to be moved apart
        // so that every chunk can carry its own length. Rare enough to be
        // worth the copy rather than a second encoding pass.
        byte[] bytes = new byte[length]; // seclume-allow: a bind value on its way out, never a secret
        for (int i = 0; i < length; i++) {
            bytes[i] = out.getByte(start + 1 + i);
        }
        out.position(start);
        putBytes(out, bytes);
    }

    /**
     * The same framing as {@link #putBytes}, reading from native memory.
     *
     * <p>Written out a second time rather than sharing, because the point of
     * the whole path is that there is no {@code byte[]} - and the sharing
     * would have to go through one. Twelve lines against a heap copy of a
     * secret is a trade worth making. See
     * {@link space.seclume.SensitiveParameters}.
     */
    private static void putNative(WireBuffer out,
            space.seclume.internal.jdbc.NativeValue value) {
        int length = value.length();
        if (length <= SHORT_LENGTH) {
            out.putByte((byte) length);
            out.putBytes(value.memory(), 0, length);
            return;
        }
        out.putByte((byte) CHUNKED);
        int at = 0;
        while (at < length) {
            int chunk = Math.min(CHUNK_SIZE, length - at);
            TtcParameters.putNumber(out, chunk);
            out.putBytes(value.memory(), at, chunk);
            at += chunk;
        }
        TtcParameters.putNumber(out, 0);
    }

    private static void putBytes(WireBuffer out, byte[] bytes) {
        if (bytes.length <= SHORT_LENGTH) {
            out.putByte((byte) bytes.length);
            out.putBytes(java.lang.foreign.MemorySegment.ofArray(bytes), 0, bytes.length);
            return;
        }
        out.putByte((byte) CHUNKED);
        int at = 0;
        while (at < bytes.length) {
            int chunk = Math.min(CHUNK_SIZE, bytes.length - at);
            TtcParameters.putNumber(out, chunk);
            out.putBytes(java.lang.foreign.MemorySegment.ofArray(bytes), at, chunk);
            at += chunk;
        }
        TtcParameters.putNumber(out, 0);
    }

    /**
     * Oracle's seven bytes for a point in time: century and year both shifted
     * by 100 - so that no byte is zero and the bytes sort - and hour, minute
     * and second shifted by one.
     */
    private static void putDate(WireBuffer out, LocalDateTime stamp) {
        out.putByte((byte) DATE_SIZE);
        int year = stamp.getYear();
        out.putByte((byte) (year / 100 + YEAR_BIAS));
        out.putByte((byte) (year % 100 + YEAR_BIAS));
        out.putByte((byte) stamp.getMonthValue());
        out.putByte((byte) stamp.getDayOfMonth());
        out.putByte((byte) (stamp.getHour() + 1));
        out.putByte((byte) (stamp.getMinute() + 1));
        out.putByte((byte) (stamp.getSecond() + 1));
    }

    /**
     * The same seven bytes and four more: the nanoseconds, most significant
     * byte first.
     *
     * <p>The length in front says eleven rather than seven, which is how the
     * server tells the two apart - the fields before the fraction are
     * identical.
     */
    private static void putTimestamp(WireBuffer out, LocalDateTime stamp) {
        int nanos = stamp.getNano();
        // Without a fraction the four bytes of nanoseconds stay away - seven
        // bytes, as a DATE is, and as ojdbc sends it: four bytes a row less
        // in a batch of timestamps.
        out.putByte((byte) (nanos == 0 ? DATE_SIZE : TIMESTAMP_SIZE));
        int year = stamp.getYear();
        out.putByte((byte) (year / 100 + YEAR_BIAS));
        out.putByte((byte) (year % 100 + YEAR_BIAS));
        out.putByte((byte) stamp.getMonthValue());
        out.putByte((byte) stamp.getDayOfMonth());
        out.putByte((byte) (stamp.getHour() + 1));
        out.putByte((byte) (stamp.getMinute() + 1));
        out.putByte((byte) (stamp.getSecond() + 1));
        if (nanos == 0) {
            return;
        }
        out.putByte((byte) (nanos >>> 24));
        out.putByte((byte) (nanos >>> 16));
        out.putByte((byte) (nanos >>> 8));
        out.putByte((byte) nanos);
    }

    /**
     * The same again with the offset behind it.
     *
     * <p>The fields in UTC and the offset beside them, which is how Oracle
     * keeps the type - so an {@code OffsetDateTime} keeps the zone it was
     * written with, which is the point of the column type.
     */
    private static void putZonedTimestamp(WireBuffer out, java.time.OffsetDateTime stamp) {
        out.putByte((byte) TIMESTAMP_ZONE_SIZE);
        // The fields in UTC, the offset beside them - how Oracle stores the
        // type. The local fields went out before, so 13:14+02:00 was stored
        // as 15:14+02:00: two hours late for every other client, and right
        // only for this driver, whose reader made the same mistake the other
        // way round. An Instant, at offset zero, was never touched by it.
        java.time.LocalDateTime local = stamp.withOffsetSameInstant(java.time.ZoneOffset.UTC)
                .toLocalDateTime();
        int year = local.getYear();
        out.putByte((byte) (year / 100 + YEAR_BIAS));
        out.putByte((byte) (year % 100 + YEAR_BIAS));
        out.putByte((byte) local.getMonthValue());
        out.putByte((byte) local.getDayOfMonth());
        out.putByte((byte) (local.getHour() + 1));
        out.putByte((byte) (local.getMinute() + 1));
        out.putByte((byte) (local.getSecond() + 1));
        int nanos = local.getNano();
        out.putByte((byte) (nanos >>> 24));
        out.putByte((byte) (nanos >>> 16));
        out.putByte((byte) (nanos >>> 8));
        out.putByte((byte) nanos);
        int seconds = stamp.getOffset().getTotalSeconds();
        out.putByte((byte) (seconds / 3600 + ZONE_HOUR_BIAS));
        out.putByte((byte) (seconds % 3600 / 60 + ZONE_MINUTE_BIAS));
    }

    /**
     * The local fields of a Timestamp, as {@code toLocalDateTime} gives them -
     * without its way through the old calendar classes, which cost more than
     * the rest of encoding the value. From 1900 on, where the two calendars
     * agree; before that the JDK's own way, which knows the Julian dates.
     */
    static LocalDateTime localFields(java.sql.Timestamp stamp) {
        return localFields(stamp, rules());
    }

    /** The same, with the zone rules already looked up. */
    static LocalDateTime localFields(java.sql.Timestamp stamp,
                                     java.time.zone.ZoneRules rules) {
        long millis = stamp.getTime();
        if (millis < SINCE_1900) {
            return stamp.toLocalDateTime();
        }
        java.time.ZoneOffset offset = offsetAt(millis, rules);
        return LocalDateTime.ofEpochSecond(Math.floorDiv(millis, 1000L), stamp.getNanos(),
                offset);
    }

    /** The zone rules for the message being written, looked up at its first timestamp. */
    private java.time.zone.ZoneRules messageRules;

    /**
     * The JVM zone's rules, once per message: {@code ZoneId.systemDefault()}
     * clones the default TimeZone on every call, which in a batch of
     * timestamps was a clone per row. A message is written in one go, and the
     * JVM's zone is the one it was when the message began.
     */
    private java.time.zone.ZoneRules messageRules() {
        if (messageRules == null) {
            messageRules = rules();
        }
        return messageRules;
    }

    /** The JVM zone and its rules, looked up once while the zone stays the same. */
    private static volatile Object[] zoneRules = {null, null};

    /**
     * The rules of the JVM's zone. {@code getRules()} goes to the provider's
     * map every time, which was a lookup per timestamp in a batch.
     */
    private static java.time.zone.ZoneRules rules() {
        java.time.ZoneId zone = java.time.ZoneId.systemDefault();
        Object[] cached = zoneRules;
        if (cached[0] != zone) {
            cached = new Object[] {zone, zone.getRules()};
            zoneRules = cached;
        }
        return (java.time.zone.ZoneRules) cached[1];
    }

    /** The offset last looked up, and the span between two transitions it holds for. */
    private record Window(java.time.zone.ZoneRules rules, long from, long to,
                          java.time.ZoneOffset offset) {
    }

    private static volatile Window window;

    /**
     * The JVM zone's offset at an instant.
     *
     * <p>{@code ZoneRules.getOffset} works out the year's transitions again for
     * every instant past the last one the zone file lists - every current
     * date - and was the largest cost left in encoding a batch of timestamps.
     * An offset holds from one transition to the next, and the rows of a batch
     * mostly fall into the same span; so the span is remembered with it.
     */
    private static java.time.ZoneOffset offsetAt(long millis,
                                                 java.time.zone.ZoneRules rules) {
        Window known = window;
        if (known != null && known.rules() == rules && millis >= known.from()
                && millis < known.to()) {
            return known.offset();
        }
        java.time.Instant instant = java.time.Instant.ofEpochMilli(millis);
        java.time.ZoneOffset offset = rules.getOffset(instant);
        long from = Long.MIN_VALUE;
        long to = Long.MAX_VALUE;
        if (!rules.isFixedOffset()) {
            java.time.zone.ZoneOffsetTransition before = rules.previousTransition(
                    instant.plusMillis(1));
            java.time.zone.ZoneOffsetTransition after = rules.nextTransition(instant);
            from = before == null ? Long.MIN_VALUE : before.getInstant().toEpochMilli();
            to = after == null ? Long.MAX_VALUE : after.getInstant().toEpochMilli();
        }
        window = new Window(rules, from, to, offset);
        return offset;
    }

    /** 1900-01-01T00:00:00Z, and a day of margin for any zone. */
    private static final long SINCE_1900 = -2_208_988_800_000L + 86_400_000L;

    /** Sixteen bytes, most significant first - what a {@code raw(16)} holds. */
    private static void putUuid(WireBuffer out, java.util.UUID id) {
        out.putByte((byte) 16);
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.putByte((byte) (id.getMostSignificantBits() >>> shift));
        }
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.putByte((byte) (id.getLeastSignificantBits() >>> shift));
        }
    }
}
