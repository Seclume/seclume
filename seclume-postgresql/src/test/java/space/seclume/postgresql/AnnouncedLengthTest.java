package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.fuzz.HostileTransport;

/**
 * A server that announces a message of almost a gigabyte and then sends it a
 * byte at a time. The receive buffer has to grow with the bytes that arrive,
 * not with the reads: until 30.09.2026 it doubled on every read, and after
 * some thirty bytes the client held - and had copied and wiped along the way
 * - a gigabyte of native memory. The dribbling fuzz sweep showed it only as
 * run time, 9 s where the other drivers take a tenth of one.
 */
@Timeout(30)
class AnnouncedLengthTest {

    @Test
    void theBufferGrowsWithTheBytesNotWithTheReads() {
        int announced = 0x3ff0_0000;                      // just under PostgreSQL's ceiling
        byte[] script = new byte[5 + 64];
        script[0] = 'T';                                  // RowDescription
        script[1] = (byte) (announced >>> 24);
        script[2] = (byte) (announced >>> 16);
        script[3] = (byte) (announced >>> 8);
        script[4] = (byte) announced;
        PgSession session = PgSession.resume(HostileTransport.of(script, 1),
                Map.of("client_encoding", "UTF8", "DateStyle", "ISO, MDY",
                        "integer_datetimes", "on", "TimeZone", "UTC", "server_version", "18.0"),
                1, 2);
        try {
            assertThrows(Exception.class, () -> session.askOneValue("select 1"));
            int capacity = session.channel().message().capacity();
            assertTrue(capacity <= 64 * 1024, "69 bytes arrived and the receive buffer holds "
                    + capacity + " bytes");
        } finally {
            session.close();
        }
    }
}
