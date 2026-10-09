package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.internal.Transport;

/**
 * The pool's reset on PostgreSQL: {@code DISCARD ALL} sent at the return,
 * its answer read before the next borrower's first message goes out - and
 * when the server refuses it, that message never goes out at all.
 */
class DeferredDiscardTest {

    @Test
    void theDiscardIsAnsweredBeforeTheNextStatementIsSent() throws Exception {
        Recording wire = new Recording(answer(complete("DISCARD ALL"), complete("SELECT 1")));
        try (PgSession session = session(wire)) {
            session.discardAllLater();
            assertEquals(1, count(wire.sent(), "discard all"));
            session.execute("select 'next borrower'");
            String sent = wire.sent();
            assertTrue(sent.indexOf("discard all") < sent.indexOf("next borrower"), sent);
            assertTrue(session.isOpen());
        }
    }

    @Test
    void aRefusedDiscardLetsNothingThrough() throws Exception {
        Recording wire = new Recording(answer(error("25001",
                "DISCARD ALL cannot run inside a transaction block")));
        try (PgSession session = session(wire)) {
            session.discardAllLater();
            SQLException refused = assertThrows(SQLException.class,
                    () -> session.execute("select 'next borrower'"));
            assertEquals("08006", refused.getSQLState());
            assertFalse(wire.sent().contains("next borrower"),
                    "the next borrower's statement reached a session that was not reset");
            assertFalse(session.isOpen());
        }
    }

    @Test
    void aSessionIsHandedOverOnlyAfterItsDiscardWasAnswered() throws Exception {
        Recording wire = new Recording(answer(complete("DISCARD ALL")));
        try (PgSession session = session(wire)) {
            session.discardAllLater();
            session.snapshot();
            assertTrue(session.isIdle(), "the answer to the discard was left on the wire");
        }
    }

    /**
     * The first execution of a plan after a return. Its Parse rides with the
     * execution, and the reset's answer is read just before it - which once
     * happened after the driver had noted which ReadyForQuery would close the
     * Parse's block. The reset's ReadyForQuery was taken for that one, the
     * Parse for failed, and the next execution sent it again: "prepared
     * statement already exists", found as the second slice of a Spring batch.
     */
    @Test
    void aPlanParsedRightAfterTheDiscardIsParsedOnce() throws Exception {
        String sql = "insert into ledger values (42)";
        Recording wire = new Recording(answer(complete("DISCARD ALL"),
                message('1'), parameters(), message('n'), message('2'), message('n'),
                complete("INSERT 0 1"),
                message('2'), message('n'), complete("INSERT 0 1")));
        try (PgSession session = session(wire)) {
            session.discardAllLater();
            session.parseLater("seclume_1", sql);
            session.bindAndExecute("seclume_1", new PgParameters(0), 0, null, null);
            assertFalse(session.hasPendingParse("seclume_1"),
                    "the Parse was taken for failed after the reset's answer");
            session.bindAndExecute("seclume_1", new PgParameters(0), 0, null, null);
            assertEquals(1, count(wire.sent(), sql), wire.sent());
        }
    }

    /** A message with no body: ParseComplete, BindComplete, NoData. */
    private static byte[] message(char tag) {
        return ByteBuffer.allocate(5).put((byte) tag).putInt(4).array();
    }

    /** ParameterDescription without parameters. */
    private static byte[] parameters() {
        return ByteBuffer.allocate(7).put((byte) 't').putInt(6).putShort((short) 0).array();
    }

    private static PgSession session(Transport wire) {
        return PgSession.resume(wire,
                Map.of("client_encoding", "UTF8", "DateStyle", "ISO, MDY",
                        "integer_datetimes", "on", "TimeZone", "UTC", "server_version", "18.0"),
                1, 2);
    }

    private static int count(String text, String part) {
        int found = 0;
        for (int at = text.indexOf(part); at >= 0; at = text.indexOf(part, at + 1)) {
            found++;
        }
        return found;
    }

    private static byte[] answer(byte[]... parts) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            all.writeBytes(part);
        }
        return all.toByteArray();
    }

    /** CommandComplete and ReadyForQuery. */
    private static byte[] complete(String tag) {
        byte[] text = tag.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer out = ByteBuffer.allocate(1 + 4 + text.length + 1 + 6);
        out.put((byte) 'C').putInt(4 + text.length + 1).put(text).put((byte) 0);
        out.put((byte) 'Z').putInt(5).put((byte) 'I');
        return out.array();
    }

    /** ErrorResponse and ReadyForQuery. */
    private static byte[] error(String state, String message) {
        byte[] code = state.getBytes(StandardCharsets.US_ASCII);
        byte[] text = message.getBytes(StandardCharsets.UTF_8);
        int body = 1 + 6 + 1 + code.length + 1 + 1 + text.length + 1 + 1;
        ByteBuffer out = ByteBuffer.allocate(1 + 4 + body + 6);
        out.put((byte) 'E').putInt(4 + body);
        out.put((byte) 'S').put("ERROR".getBytes(StandardCharsets.US_ASCII)).put((byte) 0);
        out.put((byte) 'C').put(code).put((byte) 0);
        out.put((byte) 'M').put(text).put((byte) 0);
        out.put((byte) 0);
        out.put((byte) 'Z').putInt(5).put((byte) 'T');
        return out.array();
    }

    /** Answers from a script and keeps what the driver sent. */
    private static final class Recording implements Transport {
        private final byte[] script;
        private final ByteArrayOutputStream sent = new ByteArrayOutputStream();
        private int at;
        private boolean closed;

        Recording(byte[] script) {
            this.script = script;
        }

        String sent() {
            return sent.toString(StandardCharsets.ISO_8859_1);
        }

        @Override
        public int read(ByteBuffer into) throws IOException {
            if (closed) {
                throw new IOException("closed");
            }
            if (at >= script.length) {
                return -1;
            }
            int take = Math.min(into.remaining(), script.length - at);
            into.put(script, at, take);
            at += take;
            return take;
        }

        @Override
        public int write(ByteBuffer from) {
            int wrote = from.remaining();
            byte[] bytes = new byte[wrote];
            from.get(bytes);
            sent.writeBytes(bytes);
            return wrote;
        }

        @Override
        public boolean isOpen() {
            return !closed;
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}
