package space.seclume.sqlserver.tds;

import space.seclume.internal.WireBuffer;

/**
 * The reading of a value out of its bytes.
 *
 * <p>TDS sends everything in its binary form - a {@code datetime} is eight
 * bytes, not nineteen characters. That is fast, but it means the bytes alone
 * say nothing: the column description has to supply the type, and for
 * {@code decimal} the scale as well.
 *
 * <p>The dates are the awkward part, because SQL Server has five of them and
 * each counts from a different epoch: {@code datetime} counts days from
 * 1900-01-01 in a signed integer and the time in three-hundredths of a second,
 * {@code smalldatetime} counts days in an unsigned short and the time in whole
 * minutes, and {@code date}, {@code datetime2} and {@code datetimeoffset} count
 * days from 0001-01-01 in three bytes. Mixing two of those up gives a date that
 * is off by centuries but still looks like a date.
 *
 * <p>Everything here works on {@link WireBuffer} and produces either a number
 * or protocol text. Nothing keeps a copy.
 */
public final class TdsValues {

    /** Days between 0001-01-01 and 1900-01-01 - the offset between the two epochs. */
    private static final int DAYS_1900 = 693595;
    /** Days from 0001-01-01 to 1970-01-01, the epoch {@code LocalDate} counts from. */
    private static final int DAYS_1970 = 719162;

    private TdsValues() {
    }

    /**
     * The value as an integer.
     *
     * @param type   the column type
     * @param at     start of the value in the buffer
     * @param length its length, as the row framing found it
     */
    public static long asLong(WireBuffer in, int type, int at, int length) {
        if (type == TdsTypes.SQLVARIANT) {
            Variant inner = unwrap(in, at, length);
            return asLong(in, inner.type(), inner.at(), inner.length());
        }
        return switch (type) {
            case TdsTypes.BIT, TdsTypes.BITN -> in.getByte(at) != 0 ? 1 : 0;
            case TdsTypes.INT1 -> in.getByte(at) & 0xff;
            case TdsTypes.INT2 -> (short) unsigned(in, at, 2);
            case TdsTypes.INT4 -> (int) unsigned(in, at, 4);
            case TdsTypes.INT8 -> unsigned(in, at, 8);
            case TdsTypes.INTN -> switch (length) {
                case 1 -> in.getByte(at) & 0xff;
                case 2 -> (short) unsigned(in, at, 2);
                case 4 -> (int) unsigned(in, at, 4);
                default -> unsigned(in, at, 8);
            };
            case TdsTypes.FLT4, TdsTypes.FLT8, TdsTypes.FLTN ->
                    (long) asDouble(in, type, at, length);
            default -> Long.parseLong(asText(in, type, at, length, 0).trim());
        };
    }

    /** The value as a floating-point number. */
    public static double asDouble(WireBuffer in, int type, int at, int length) {
        if (type == TdsTypes.SQLVARIANT) {
            Variant inner = unwrap(in, at, length);
            return asDouble(in, inner.type(), inner.at(), inner.length());
        }
        return switch (type) {
            case TdsTypes.FLT4 -> Float.intBitsToFloat((int) unsigned(in, at, 4));
            case TdsTypes.FLT8 -> Double.longBitsToDouble(unsigned(in, at, 8));
            case TdsTypes.FLTN -> length == 4
                    ? Float.intBitsToFloat((int) unsigned(in, at, 4))
                    : Double.longBitsToDouble(unsigned(in, at, 8));
            case TdsTypes.BIT, TdsTypes.BITN, TdsTypes.INT1, TdsTypes.INT2, TdsTypes.INT4,
                 TdsTypes.INT8, TdsTypes.INTN -> asLong(in, type, at, length);
            default -> Double.parseDouble(asText(in, type, at, length, 0).trim());
        };
    }

    /**
     * The value as text - the form a {@code getString} is expected to return.
     *
     * @param scale the scale from the column description; only the decimal and
     *              time types use it
     */
    public static String asText(WireBuffer in, int type, int at, int length, int scale) {
        return asText(in, type, at, length, scale, java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    /**
     * The same, with the code page single-byte text is in - the column's
     * collation, see {@link TdsCollation}.
     */
    public static String asText(WireBuffer in, int type, int at, int length, int scale,
            java.nio.charset.Charset charset) {
        if (type == TdsTypes.SQLVARIANT) {
            Variant inner = unwrap(in, at, length);
            return asText(in, inner.type(), inner.at(), inner.length(), inner.scale(),
                    inner.charset() == null ? charset : inner.charset());
        }
        return switch (type) {
            case TdsTypes.BIT, TdsTypes.BITN -> in.getByte(at) != 0 ? "1" : "0";
            case TdsTypes.INT1, TdsTypes.INT2, TdsTypes.INT4, TdsTypes.INT8, TdsTypes.INTN ->
                    Long.toString(asLong(in, type, at, length));
            case TdsTypes.FLT4, TdsTypes.FLTN, TdsTypes.FLT8 -> {
                double value = asDouble(in, type, at, length);
                yield length == 4 ? Float.toString((float) value) : Double.toString(value);
            }
            case TdsTypes.DECIMAL, TdsTypes.DECIMALN, TdsTypes.NUMERIC, TdsTypes.NUMERICN ->
                    decimal(in, at, length, scale);
            case TdsTypes.MONEY, TdsTypes.MONEYN, TdsTypes.MONEY4 -> money(in, at, length);
            case TdsTypes.DATETIME, TdsTypes.DATETIM4, TdsTypes.DATETIMN ->
                    dateTime(in, at, length);
            case TdsTypes.DATEN -> date(days(in, at));
            case TdsTypes.TIMEN -> time(timeTicks(in, at, length), scale);
            case TdsTypes.DATETIME2N -> {
                int timeBytes = length - 3;
                yield date(days(in, at + timeBytes)) + " "
                        + time(timeTicks(in, at, timeBytes), scale);
            }
            case TdsTypes.DATETIMEOFFSETN -> {
                // The fields on the wire are UTC and the offset stands
                // beside them - so the local time the value names is the
                // fields plus the offset. Printing the UTC fields with the
                // offset behind them names a different point in time, off by
                // exactly the offset: a value written as 11:29+02:00 read
                // back as 09:29+02:00. The writer already knew this; the
                // reader did not.
                int timeBytes = length - 5;
                int offsetMinutes = (short) unsigned(in, at + timeBytes + 3, 2);
                long ticks = timeTicks(in, at, timeBytes);
                long perSecond = ticksPerSecond(scale);
                long ticksPerDay = 86_400L * perSecond;
                long shifted = ticks + offsetMinutes * 60L * perSecond;
                // Arithmetic, not a loop that steps a day at a time: a
                // hostile value would otherwise take billions of steps.
                int days = (int) (days(in, at + timeBytes) + Math.floorDiv(shifted, ticksPerDay));
                shifted = Math.floorMod(shifted, ticksPerDay);
                yield date(days) + " " + time(shifted, scale) + " " + offset(offsetMinutes);
            }
            case TdsTypes.GUID -> guid(in, at);
            // Binary as hex, not as characters. Decoding the bytes of a
            // varbinary through the ASCII path produced whatever those bytes
            // happen to look like as text - for 00 01 02 FF 80 a string of
            // control characters and a replacement character, which is not a
            // representation of anything and loses the value. mssql-jdbc
            // answers with uppercase hex and so does this now.
            case TdsTypes.BINARY, TdsTypes.BIGBINARY, TdsTypes.VARBINARY,
                 TdsTypes.BIGVARBINARY, TdsTypes.IMAGE, TdsTypes.UDT -> hex(in, at, length);
            default -> {
                if (TdsTypes.isUnicodeText(type)) {
                    yield utf16(in, at, length / 2);
                }
                yield ascii(in, at, length, charset);
            }
        };
    }

    /** The raw bytes of the value - for {@code binary}, {@code varbinary}, {@code image}. */
    public static byte[] asBytes(WireBuffer in, int at, int length) {
        byte[] value = new byte[length]; // seclume-allow: payload the caller asked for, not a secret
        for (int i = 0; i < length; i++) {
            value[i] = in.getByte(at + i);
        }
        return value;
    }

    /** Whether the value is true - {@code bit} and everything that counts as a number. */
    public static boolean asBoolean(WireBuffer in, int type, int at, int length) {
        if (type == TdsTypes.SQLVARIANT) {
            Variant inner = unwrap(in, at, length);
            return asBoolean(in, inner.type(), inner.at(), inner.length());
        }
        if (TdsTypes.isUnicodeText(type) || TdsTypes.isSingleByteText(type)) {
            String text = asText(in, type, at, length, 0).trim();
            return !text.isEmpty() && !text.equals("0")
                    && (text.charAt(0) == 't' || text.charAt(0) == 'T'
                        || text.charAt(0) == 'y' || text.charAt(0) == 'Y'
                        || !text.equals("false"));
        }
        return asLong(in, type, at, length) != 0;
    }

    // ---- the individual formats ------------------------------------------

    /** What a {@code sql_variant} turned out to be holding. */
    private record Variant(int type, int at, int length, int scale,
                           java.nio.charset.Charset charset) {
    }

    /**
     * Unpacks a {@code sql_variant}: one byte of base type, one byte saying
     * how many property bytes follow, those properties, then the value.
     *
     * <p>The property count is read <b>off the wire</b> rather than looked up
     * in a table of types. That matters: a base type nobody here anticipated
     * still lands on the right first byte of the value instead of being
     * decoded from somewhere in the middle of its own description. Only the
     * two families whose properties change how a value reads - the decimals
     * and the time types - are interpreted at all, and both put what is
     * needed at a fixed place within their properties.
     */
    private static Variant unwrap(WireBuffer in, int at, int length) {
        int base = in.getByte(at) & 0xff;
        int properties = in.getByte(at + 1) & 0xff;
        int scale = switch (base) {
            case TdsTypes.DECIMAL, TdsTypes.DECIMALN, TdsTypes.NUMERIC, TdsTypes.NUMERICN ->
                    in.getByte(at + 3) & 0xff;                 // precision first, then scale
            case TdsTypes.TIMEN, TdsTypes.DATETIME2N, TdsTypes.DATETIMEOFFSETN ->
                    in.getByte(at + 2) & 0xff;
            default -> 0;
        };
        // Single-byte text carries its collation in the first five property
        // bytes, as a column does in its description.
        java.nio.charset.Charset charset = (base == TdsTypes.BIGVARCHAR
                || base == TdsTypes.BIGCHAR) && properties >= 5
                ? ColumnMetadata.collation(in, at + 2) : null;
        return new Variant(base, at + 2 + properties, length - 2 - properties, scale, charset);
    }

    /** The type a {@code sql_variant} value turned out to hold - its first byte. */
    public static int variantBase(WireBuffer in, int at) {
        return in.getByte(at) & 0xff;
    }

    /** An unsigned number of {@code count} bytes, least significant first. */
    private static long unsigned(WireBuffer in, int at, int count) {
        long value = 0;
        for (int i = count - 1; i >= 0; i--) {
            value = (value << 8) | (in.getByte(at + i) & 0xffL);
        }
        return value;
    }

    /**
     * {@code decimal} and {@code numeric}: one sign byte, then the magnitude as
     * up to sixteen bytes, least significant first.
     *
     * <p>The digits are produced by repeatedly dividing by a power of ten -
     * without {@code BigInteger}, which would put the whole number on the heap
     * as an immutable object.
     */
    private static String decimal(WireBuffer in, int at, int length, int scale) {
        boolean positive = in.getByte(at) != 0;
        int magnitudeBytes = length - 1;
        if (magnitudeBytes <= 8) {
            // Up to nineteen digits - every decimal(18) and most beyond it -
            // fit a long: one Long.toString instead of a division per nine
            // digits and three reversed builders.
            long magnitude = unsigned(in, at + 1, magnitudeBytes);
            if (magnitude >= 0) {
                return withScale(Long.toString(magnitude), scale, positive);
            }
        }
        int[] limbs = new int[(magnitudeBytes + 3) / 4]; // seclume-allow: a numeric payload value, not a secret
        for (int i = 0; i < magnitudeBytes; i++) {
            limbs[i / 4] |= (in.getByte(at + 1 + i) & 0xff) << ((i % 4) * 8);
        }
        String digits = digitsOf(limbs);
        return withScale(digits, scale, positive);
    }

    /**
     * A {@code decimal} as a BigDecimal straight from its bytes - no text in
     * between for the ones that fit a long.
     */
    public static java.math.BigDecimal asBigDecimal(WireBuffer in, int type, int at, int length,
            int scale) {
        if ((type == TdsTypes.DECIMALN || type == TdsTypes.NUMERICN
                || type == TdsTypes.DECIMAL || type == TdsTypes.NUMERIC) && length - 1 <= 8) {
            long magnitude = unsigned(in, at + 1, length - 1);
            if (magnitude >= 0) {
                return java.math.BigDecimal.valueOf(in.getByte(at) != 0 ? magnitude : -magnitude,
                        scale);
            }
        }
        return new java.math.BigDecimal(asText(in, type, at, length, scale).trim());
    }

    /** Decimal digits of a little-endian limb array; "0" when it is zero. */
    private static String digitsOf(int[] limbs) {
        StringBuilder reversed = new StringBuilder(); // seclume-allow: a numeric payload value, not a secret
        boolean zero = false;
        while (!zero) {
            long remainder = 0;
            zero = true;
            for (int i = limbs.length - 1; i >= 0; i--) {
                long current = (remainder << 32) | (limbs[i] & 0xffffffffL);
                long quotient = current / 1_000_000_000L;
                remainder = current - quotient * 1_000_000_000L;
                limbs[i] = (int) quotient;
                if (limbs[i] != 0) {
                    zero = false;
                }
            }
            // Nine digits per round; leading zeroes only matter while more
            // limbs remain, which is exactly what `zero` says.
            String piece = Long.toString(remainder);
            if (!zero) {
                reversed.append(new StringBuilder(piece).reverse());
                for (int i = piece.length(); i < 9; i++) {
                    reversed.append('0');
                }
            } else {
                reversed.append(new StringBuilder(piece).reverse());
            }
        }
        String digits = reversed.reverse().toString();
        int firstSignificant = 0;
        while (firstSignificant < digits.length() - 1 && digits.charAt(firstSignificant) == '0') {
            firstSignificant++;
        }
        return digits.substring(firstSignificant);
    }

    /** Puts the decimal point in and the sign in front. */
    private static String withScale(String digits, int scale, boolean positive) {
        // A negative zero prints as zero; the magnitude is zero exactly when
        // its digits are - no regular expression per value, which is what
        // this cost before.
        boolean zero = true;
        for (int i = 0; i < digits.length() && zero; i++) {
            zero = digits.charAt(i) == '0';
        }
        StringBuilder text = new StringBuilder(digits.length() + scale + 3); // seclume-allow: a numeric payload value, not a secret
        if (!positive && !zero) {
            text.append('-');
        }
        int whole = digits.length() - scale;
        if (whole <= 0) {
            text.append('0');
        } else {
            text.append(digits, 0, whole);
        }
        if (scale > 0) {
            text.append('.');
            for (int i = whole; i < 0; i++) {
                text.append('0');
            }
            text.append(digits, Math.max(whole, 0), digits.length());
        }
        return text.toString();
    }

    /** {@code money} counts ten-thousandths - the high half comes first. */
    private static String money(WireBuffer in, int at, int length) {
        long value;
        if (length == 4) {
            value = (int) unsigned(in, at, 4);
        } else {
            long high = (int) unsigned(in, at, 4);
            long low = unsigned(in, at + 4, 4);
            value = (high << 32) | low;
        }
        boolean negative = value < 0;
        long magnitude = Math.abs(value);
        String digits = Long.toString(magnitude);
        return withScale(digits, 4, !negative);
    }

    /** {@code datetime} and {@code smalldatetime}. */
    private static String dateTime(WireBuffer in, int at, int length) {
        if (length == 4) {
            int days = (int) unsigned(in, at, 2);
            int minutes = (int) unsigned(in, at + 2, 2);
            // ".0" as Timestamp.toString and so mssql-jdbc write it
            return date(DAYS_1900 + days) + " " + time(minutes * 60L, 0) + ".0";
        }
        int days = (int) unsigned(in, at, 4);
        long ticks = unsigned(in, at + 4, 4);
        // Three-hundredths of a second, so 10/3 milliseconds each.
        long millis = ticks * 10L / 3L;
        return date(DAYS_1900 + days) + " " + time(millis, 3);
    }

    /** Three bytes of days since 0001-01-01, least significant first. */
    private static int days(WireBuffer in, int at) {
        return (int) unsigned(in, at, 3);
    }

    /**
     * The time as nanoseconds since midnight.
     *
     * <p>On the wire it is a count of {@code 10^-scale} seconds in three to five
     * bytes - which of the three is decided by the scale and thus by the column
     * description, not by the value.
     */
    private static long timeTicks(WireBuffer in, int at, int lengthBytes) {
        if (lengthBytes < 3 || lengthBytes > 5) {
            throw WireBuffer.malformed("a time of " + lengthBytes + " bytes");
        }
        return unsigned(in, at, lengthBytes);
    }

    /** SQL Server's finest time: 100 ns, scale 7. A larger one is not from a server. */
    static final int MAX_TIME_SCALE = 7;

    private static long ticksPerSecond(int scale) {
        if (scale < 0 || scale > MAX_TIME_SCALE) {
            throw WireBuffer.malformed("a time scale of " + scale);
        }
        long divisor = 1;
        for (int i = 0; i < scale; i++) {
            divisor *= 10;
        }
        return divisor;
    }

    /** {@code YYYY-MM-DD} from a day count since 0001-01-01. */
    private static String date(int daysSinceYearOne) {
        return java.time.LocalDate.ofEpochDay(daysSinceYearOne - DAYS_1970).toString();
    }

    /** {@code HH:MM:SS[.fff…]} from a tick count, the scale deciding the unit. */
    private static String time(long ticks, int scale) {
        long divisor = ticksPerSecond(scale);
        long seconds = ticks / divisor;
        long fraction = ticks - seconds * divisor;
        StringBuilder text = new StringBuilder(); // seclume-allow: a timestamp payload value, not a secret
        append2(text, seconds / 3600);
        text.append(':');
        append2(text, (seconds / 60) % 60);
        text.append(':');
        append2(text, seconds % 60);
        if (scale > 0) {
            text.append('.');
            String digits = Long.toString(fraction);
            for (int i = digits.length(); i < scale; i++) {
                text.append('0');
            }
            text.append(digits);
        }
        return text.toString();
    }

    /** The time-zone offset of a {@code datetimeoffset}, as {@code +HH:MM}. */
    private static String offset(int minutes) {
        StringBuilder text = new StringBuilder(); // seclume-allow: a timestamp payload value, not a secret
        text.append(minutes < 0 ? '-' : '+');
        int absolute = Math.abs(minutes);
        append2(text, absolute / 60);
        text.append(':');
        append2(text, absolute % 60);
        return text.toString();
    }

    private static void append2(StringBuilder text, long value) {
        if (value < 10) {
            text.append('0');
        }
        text.append(value);
    }

    /** Uppercase hex, the way SQL Server and its own driver write binary. */
    private static String hex(WireBuffer in, int at, int length) {
        StringBuilder text = new StringBuilder(length * 2); // seclume-allow: a payload value, not a secret
        for (int i = 0; i < length; i++) {
            int value = in.getByte(at + i) & 0xff;
            text.append(Character.toUpperCase(Character.forDigit(value >>> 4, 16)));
            text.append(Character.toUpperCase(Character.forDigit(value & 0x0f, 16)));
        }
        return text.toString();
    }

    /**
     * {@code uniqueidentifier}: the first three groups are little-endian, the
     * last two are not. A GUID printed the wrong way round still looks like a
     * GUID, which is why this is spelled out here.
     */
    private static String guid(WireBuffer in, int at) {
        int[] order = {3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15};
        StringBuilder text = new StringBuilder(36); // seclume-allow: a payload value, not a secret
        for (int index : order) {
            if (index < 0) {
                text.append('-');
            } else {
                int value = in.getByte(at + index) & 0xff;
                // Upper case: that is how SQL Server renders a
                // uniqueidentifier and how mssql-jdbc reads one back, and a
                // GUID that differs only in case still compares unequal as a
                // string.
                text.append(Character.toUpperCase(Character.forDigit(value >>> 4, 16)));
                text.append(Character.toUpperCase(Character.forDigit(value & 0x0f, 16)));
            }
        }
        return text.toString();
    }

    /** UTF-16LE from the buffer; {@code chars} is the number of characters. */
    private static String utf16(WireBuffer in, int at, int chars) {
        // One bulk copy and the JDK's decoder, which compacts to Latin-1 where
        // it can - rather than a char at a time into an array that the String
        // constructor then copies and compresses once more.
        byte[] bytes = new byte[chars * 2]; // seclume-allow: payload the caller asked for, not a secret
        // Through slice, which checks the bounds as getByte does: a length off
        // a hostile wire ends as WireBuffer.Truncated, not as an
        // IndexOutOfBoundsException from the copy.
        java.lang.foreign.MemorySegment.copy(in.slice(at, bytes.length),
                java.lang.foreign.ValueLayout.JAVA_BYTE, 0, bytes, 0, bytes.length);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_16LE); // seclume-allow: payload the caller asked for, not a secret
    }

    /**
     * Single-byte text.
     *
     * <p>In the code page of the column's collation - see {@link TdsCollation}.
     * It was Latin-1 for every column, which read the euro sign, Cyrillic and
     * every CJK text wrong; the claim this comment used to make, that the
     * default collations are Latin-1, was wrong too - they are code page 1252.
     */
    private static String ascii(WireBuffer in, int at, int length,
            java.nio.charset.Charset charset) {
        byte[] bytes = new byte[length]; // seclume-allow: payload the caller asked for, not a secret
        java.lang.foreign.MemorySegment.copy(in.slice(at, length),
                java.lang.foreign.ValueLayout.JAVA_BYTE, 0, bytes, 0, length);
        return new String(bytes, charset); // seclume-allow: payload the caller asked for, not a secret
    }
}
