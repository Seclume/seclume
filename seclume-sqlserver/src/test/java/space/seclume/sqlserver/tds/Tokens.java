package space.seclume.sqlserver.tds;

import java.io.ByteArrayOutputStream;

import space.seclume.internal.WireBuffer;

/**
 * Builds token streams by hand, for the tests.
 *
 * <p>The parser is the piece that cannot be checked by looking at it: a
 * misread length in TDS produces no error but a shifted read, and the values
 * after it turn into plausible nonsense. The only way to be sure is to put in
 * bytes whose meaning is known and compare what comes out.
 *
 * <p>Everything here is written the way {@code MS-TDS} describes it, not the
 * way the parser reads it - otherwise the test would only confirm the parser's
 * own idea of the protocol.
 */
final class Tokens {

    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

    Tokens u8(int value) {
        bytes.write(value & 0xff);
        return this;
    }

    Tokens u16(int value) {
        return u8(value).u8(value >>> 8);
    }

    Tokens i32(int value) {
        return u16(value).u16(value >>> 16);
    }

    Tokens i64(long value) {
        return i32((int) value).i32((int) (value >>> 32));
    }

    Tokens raw(int... values) {
        for (int value : values) {
            u8(value);
        }
        return this;
    }

    /** UTF-16LE without a length in front. */
    Tokens utf16(String text) {
        for (int i = 0; i < text.length(); i++) {
            u16(text.charAt(i));
        }
        return this;
    }

    /** A one-byte character count, then the text. */
    Tokens bString(String text) {
        return u8(text.length()).utf16(text);
    }

    /** A two-byte character count, then the text. */
    Tokens usString(String text) {
        return u16(text.length()).utf16(text);
    }

    /** The five collation bytes that follow every text type. */
    Tokens collation() {
        return raw(0x09, 0x04, 0xd0, 0x00, 0x34);
    }

    // ---- whole tokens ----------------------------------------------------

    /** COLMETADATA with its column count; the columns follow. */
    Tokens colMetadata(int columns) {
        return u8(Tds.TOKEN_COLMETADATA).u16(columns);
    }

    /** A column whose type carries a one-byte size: {@code intn}, {@code bitn}. */
    Tokens columnOneByte(String name, int type, int size, boolean nullable) {
        return i32(0).u16(nullable ? 1 : 0).u8(type).u8(size).bString(name);
    }

    /** A fixed-length column: {@code int}, {@code datetime} and their kind. */
    Tokens columnFixed(String name, int type) {
        return i32(0).u16(0).u8(type).bString(name);
    }

    /** {@code nvarchar} and friends: two-byte size plus collation. */
    Tokens columnText(String name, int type, int size, boolean nullable) {
        return i32(0).u16(nullable ? 1 : 0).u8(type).u16(size).collation().bString(name);
    }

    /** {@code date}: the only type whose description carries nothing at all. */
    Tokens columnDate(String name) {
        return i32(0).u16(1).u8(TdsTypes.DATEN).bString(name);
    }

    /** {@code time}, {@code datetime2}, {@code datetimeoffset}: a scale, no length. */
    Tokens columnTime(String name, int type, int scale) {
        return i32(0).u16(1).u8(type).u8(scale).bString(name);
    }

    /** {@code decimal}: one-byte size, then precision and scale. */
    Tokens columnDecimal(String name, int size, int precision, int scale) {
        return i32(0).u16(1).u8(TdsTypes.DECIMALN).u8(size).u8(precision).u8(scale)
                .bString(name);
    }

    Tokens row() {
        return u8(Tds.TOKEN_ROW);
    }

    /** NBCROW with its NULL bitmask; {@code nullColumns} are the NULL ones. */
    Tokens nbcRow(int columns, int... nullColumns) {
        u8(Tds.TOKEN_NBCROW);
        byte[] mask = new byte[(columns + 7) / 8];
        for (int column : nullColumns) {
            mask[column / 8] |= (byte) (1 << (column % 8));
        }
        for (byte b : mask) {
            u8(b);
        }
        return this;
    }

    /** A value with a one-byte length. */
    Tokens cell1(int... value) {
        return u8(value.length).raw(value);
    }

    /** A value with a two-byte length. */
    Tokens cell2(int... value) {
        return u16(value.length).raw(value);
    }

    /** Text with a two-byte byte count. */
    Tokens cellText(String text) {
        return u16(text.length() * 2).utf16(text);
    }

    /** A MAX value: total length, then the chunks, then a zero chunk. */
    Tokens plpText(long total, String... chunks) {
        i64(total);
        for (String chunk : chunks) {
            i32(chunk.length() * 2).utf16(chunk);
        }
        return i32(0);
    }

    /** A NULL in the MAX framing. */
    Tokens plpNull() {
        return i64(-1L);
    }

    /** ERROR or INFO with its length worked out. */
    Tokens message(boolean error, int number, int severity, String text) {
        Tokens body = new Tokens();
        body.i32(number).u8(1).u8(severity).usString(text)
                .bString("server").bString("").i32(1);
        byte[] payload = body.bytes.toByteArray();
        u8(error ? Tds.TOKEN_ERROR : Tds.TOKEN_INFO).u16(payload.length);
        bytes.write(payload, 0, payload.length);
        return this;
    }

    /** ENVCHANGE of kind 1: the database changed. */
    Tokens databaseChanged(String to, String from) {
        Tokens body = new Tokens();
        body.u8(1).bString(to).bString(from);
        byte[] payload = body.bytes.toByteArray();
        u8(Tds.TOKEN_ENVCHANGE).u16(payload.length);
        bytes.write(payload, 0, payload.length);
        return this;
    }

    Tokens done(int status, long rowCount) {
        return u8(Tds.TOKEN_DONE).u16(status).u16(0xc1).i64(rowCount);
    }

    // ---- the result ------------------------------------------------------

    int length() {
        return bytes.size();
    }

    /** The stream in a buffer, as it would come off the channel. */
    WireBuffer buffer() {
        byte[] content = bytes.toByteArray();
        WireBuffer buffer = new WireBuffer(Math.max(64, content.length + 16));
        for (byte b : content) {
            buffer.putByte(b);
        }
        buffer.position(0);
        buffer.limit(content.length);
        return buffer;
    }
}
