package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.sql.SQLException;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;
import space.seclume.tck.fuzz.HostileTransport;

/**
 * A row value whose four-byte length is negative, or so large that the reader
 * wraps round. Found by the nightly fuzz run on 06.10.2026
 * (TdsDecoderFuzzTest#coverageGuided): {@code sql_variant}, {@code text},
 * {@code ntext} and {@code image} carry a signed four-byte length, and the row
 * reader added it to its position unchecked. Minus five put the reader back on
 * the {@code ROW} token it had just read, the token stream read that row
 * again, and the session never returned.
 *
 * <p>Every case has to end - which is why each one runs under a deadline - and
 * end as an {@link IOException}, which the session turns into a SQLException.
 */
class TdsRowMalformedTest {

    private static final Duration DEADLINE = Duration.ofSeconds(5);

    /** The sql_variant type, which has no text pointer before its length. */
    private static final int SQLVARIANT = 0x62;
    /** image: a text pointer and a timestamp, then the length. */
    private static final int IMAGE = 0x22;

    /** COLMETADATA for one nullable column of a four-byte-length type. */
    private static void column(ByteArrayOutputStream out, int type) {
        out.write(0x81);
        out.writeBytes(new byte[] {0x01, 0x00});            // one column
        out.writeBytes(new byte[] {0x00, 0x00, 0x00, 0x00}); // user type
        out.writeBytes(new byte[] {0x09, 0x00});            // flags: nullable
        out.write(type);
        out.writeBytes(le(8000));                           // maximum length
        if (type == IMAGE) {
            out.write(0x00);                                // no table name parts
        }
        out.write(0x01);                                    // name: one character
        out.writeBytes(new byte[] {'n', 0x00});
    }

    /** A ROW with one value of {@code length} bytes, as the column's type frames it. */
    private static void row(ByteArrayOutputStream out, int type, int length) {
        out.write(0xd1);
        if (type == IMAGE) {
            out.write(0x10);                                // text pointer: 16 bytes
            out.writeBytes(new byte[16]);
            out.writeBytes(new byte[8]);                    // timestamp
        }
        out.writeBytes(le(length));
    }

    private static void done(ByteArrayOutputStream out) {
        out.write(0xfd);
        out.writeBytes(new byte[] {0x10, 0x00, 0x00, 0x00});
        out.writeBytes(new byte[] {0x01, 0, 0, 0, 0, 0, 0, 0});
    }

    private static byte[] le(int value) {
        return new byte[] {(byte) value, (byte) (value >> 8),
            (byte) (value >> 16), (byte) (value >> 24)};
    }

    /** The tokens of one answer: a column, a row whose value says {@code length}, DONE. */
    private static byte[] tokens(int type, int length) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        column(out, type);
        row(out, type, length);
        done(out);
        return out.toByteArray();
    }

    private static WireBuffer buffer(byte[] bytes) {
        WireBuffer in = new WireBuffer(bytes.length + 16);
        for (byte b : bytes) {
            in.putByte(b);
        }
        in.position(0);
        in.limit(bytes.length);
        return in;
    }

    /** The answer read the way a session reads it, packet by packet. */
    private static void readAsTheSessionDoes(byte[] tokens) {
        try (WireBuffer in = buffer(tokens)) {
            IOException refused = assertThrows(IOException.class, () ->
                    assertTimeoutPreemptively(DEADLINE, () ->
                            new TokenStream().readComplete(in, 0, tokens.length, row -> { })));
            assertTrue(refused.getMessage() != null && !refused.getMessage().isBlank());
        }
    }

    @Test
    void aVariantWhoseLengthIsNegativeIsRefused() {
        // FB FF FF FF: minus five, exactly back onto the ROW token
        readAsTheSessionDoes(tokens(SQLVARIANT, -5));
    }

    @Test
    void anImageWhoseLengthIsNegativeIsRefused() {
        // back over the text pointer and the timestamp to the ROW token
        readAsTheSessionDoes(tokens(IMAGE, -30));
        readAsTheSessionDoes(tokens(IMAGE, -1));
    }

    @Test
    void aLengthThatWrapsRoundIsRefused() {
        readAsTheSessionDoes(tokens(SQLVARIANT, Integer.MAX_VALUE));
        readAsTheSessionDoes(tokens(IMAGE, Integer.MAX_VALUE));
        readAsTheSessionDoes(tokens(SQLVARIANT, Integer.MIN_VALUE));
    }

    @Test
    void aLengthPastWhatHasArrivedStillWaitsForTheRest() throws Exception {
        // Positive and in range, only not here yet: the next packet may bring
        // it, so this is not a malformed answer - readComplete stops in front
        // of the row and says so.
        byte[] tokens = tokens(SQLVARIANT, 100);
        int rowAt = tokens.length - 13 - 5;
        try (WireBuffer in = buffer(tokens)) {
            assertEquals(rowAt, new TokenStream().readComplete(in, 0, tokens.length, row -> { }));
        }
    }

    /** The finding as it arrived: one packet, through a session, against the contract. */
    @Test
    void theSessionReturnsAndClosesItself() {
        byte[] payload = tokens(SQLVARIANT, -5);
        int length = 8 + payload.length;
        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        packet.writeBytes(new byte[] {0x04, 0x01, (byte) (length >> 8), (byte) length,
            0x00, 0x33, 0x01, 0x00});
        packet.writeBytes(payload);

        TdsSession session = TdsSession.resume(HostileTransport.of(packet.toByteArray()),
                4096, "master", "seclume", 16);
        try {
            SQLException failed = assertThrows(SQLException.class, () ->
                    assertTimeoutPreemptively(DEADLINE, () -> session.askOneValue("select n from t")));
            assertTrue(String.valueOf(failed.getSQLState()).startsWith("08"),
                    "a broken answer is a broken connection: " + failed.getSQLState());
            assertFalse(session.isOpen(), "its stream is somewhere nobody can make sense of");
        } finally {
            session.close();
        }
    }
}
