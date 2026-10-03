package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.tck.fuzz.HostileTransport;

class BufferedNotificationTest {
    @Test
    void aNotificationBufferedAfterReadyCanStillBeTaken() throws Exception {
        try (PgSession session = session(answer())) {
            assertTrue(session.takeNotifications(true).isEmpty());
            assertFalse(session.isIdle(), "unread bytes must still prevent an idle state");
            var arrived = session.takeNotifications(true);
            assertEquals(1, arrived.size());
            assertEquals("orders", arrived.getFirst().channel());
            assertEquals("now", arrived.getFirst().payload());
            assertEquals(42, arrived.getFirst().processId());
            assertTrue(session.isIdle());
            assertTrue(session.takeNotifications(false).isEmpty(), "delivered only once");
        }
    }

    @Test
    void pollingDoesNotFlushPendingCommandsOrReadPinnedRows() throws Exception {
        try (PgSession session = session(new byte[0])) {
            session.channel().keepBuffer(true);
            assertTrue(session.takeNotifications(true).isEmpty());
            session.channel().keepBuffer(false);
            session.channel().begin(PgProtocol.SYNC);
            session.channel().end();
            assertTrue(session.takeNotifications(true).isEmpty());
            assertEquals(5, session.channel().pending());
            session.channel().flush();
            assertTrue(session.takeNotifications(true).isEmpty(), "an answer is still in flight");
            assertEquals(1, session.channel().roundTrips(), "polling must not send another Sync");
        }
    }

    private static PgSession session(byte[] answer) {
        return PgSession.resume(HostileTransport.of(answer),
                Map.of("client_encoding", "UTF8", "DateStyle", "ISO, MDY",
                        "integer_datetimes", "on", "TimeZone", "UTC", "server_version", "18.0"),
                1, 2);
    }

    private static byte[] answer() {
        ByteBuffer answer = ByteBuffer.allocate(64);
        ready(answer);
        byte[] channel = "orders".getBytes(StandardCharsets.UTF_8);
        byte[] payload = "now".getBytes(StandardCharsets.UTF_8);
        answer.put((byte) 'A').putInt(4 + 4 + channel.length + 1 + payload.length + 1);
        answer.putInt(42).put(channel).put((byte) 0).put(payload).put((byte) 0);
        ready(answer);
        return java.util.Arrays.copyOf(answer.array(), answer.position());
    }

    private static void ready(ByteBuffer answer) {
        answer.put((byte) 'Z').putInt(5).put((byte) 'I');
    }
}
