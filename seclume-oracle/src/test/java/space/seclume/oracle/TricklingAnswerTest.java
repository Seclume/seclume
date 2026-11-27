package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.ResourceLock;

import space.seclume.internal.SocketTransport;
import space.seclume.oracle.jdbc.OraConnection;
import space.seclume.oracle.net.NsPacket;

/**
 * An Oracle that ignores the break and answers a byte every 200 ms: never
 * silent, so a timeout counting silence never fires. The query timeout and
 * the grace bound the statement, and the connection is closed.
 */
@Timeout(60)
@ResourceLock("seclume.queryTimeoutGraceSeconds")
class TricklingAnswerTest {

    @Test
    void aTricklingAnswerIsBoundedByTheQueryTimeoutAndTheGrace() throws Exception {
        String before = System.getProperty("seclume.queryTimeoutGraceSeconds");
        System.setProperty("seclume.queryTimeoutGraceSeconds", "1");
        AtomicBoolean stop = new AtomicBoolean();
        try (ServerSocket listener = new ServerSocket()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            Thread server = Thread.ofPlatform().daemon().start(() -> {
                try (Socket socket = listener.accept()) {
                    InputStream in = socket.getInputStream();
                    OutputStream out = socket.getOutputStream();
                    byte[] header = new byte[8];
                    in.readNBytes(header, 0, 8);                       // the call's NS header
                    int length = ((header[0] & 0xff) << 8) | (header[1] & 0xff);
                    in.readNBytes(length - 8);
                    // A data packet of 8 KiB announced, its payload a byte at a time.
                    out.write(new byte[] {0x20, 0x00, 0x00, 0x00, (byte) NsPacket.TYPE_DATA, 0x00,
                        0x00, 0x00});
                    out.flush();
                    while (!stop.get()) {
                        out.write(0x00);
                        out.flush();
                        Thread.sleep(200);
                    }
                } catch (IOException | InterruptedException gone) {
                    // the client closed - what it should do
                }
            });
            OracleSession session = OracleSession.resume(SocketTransport.wrap(
                    java.nio.channels.SocketChannel.open(listener.getLocalSocketAddress())),
                    NsPacket.VERSION_MIN_LARGE_SDU - 1, 1, false);
            try (Connection connection = OraConnection.resume(session,
                    space.seclume.internal.jdbc.ConnectionFacts.fresh(
                            Connection.TRANSACTION_READ_COMMITTED));
                 Statement statement = connection.createStatement()) {
                statement.setQueryTimeout(1);
                long started = System.nanoTime();
                assertThrows(SQLException.class,
                        () -> statement.executeQuery("select * from big").close());
                long took = (System.nanoTime() - started) / 1_000_000;
                assertTrue(took >= 1_900 && took < 6_000,
                        "took " + took + " ms - not the timeout and the grace");
                assertFalse(connection.isValid(1), "the connection is still in use");
            } finally {
                stop.set(true);
                server.join(5_000);
            }
        } finally {
            if (before == null) {
                System.clearProperty("seclume.queryTimeoutGraceSeconds");
            } else {
                System.setProperty("seclume.queryTimeoutGraceSeconds", before);
            }
        }
    }
}
