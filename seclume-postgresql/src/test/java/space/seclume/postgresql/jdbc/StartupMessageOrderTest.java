package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import space.seclume.secret.NoSecretProvider;

/**
 * The StartupMessage as the server reads it: protocol 3.0, then name and
 * value pairs - user, database, application_name, client_encoding first and
 * in that order, extra_float_digits among the rest - each name once, and the
 * values as they were set, byte for byte. A server takes the last of two
 * equal names; one that came twice would let a later value override what
 * the application set.
 */
class StartupMessageOrderTest {

    private static List<String[]> pairs(byte[] body) {
        List<String[]> found = new ArrayList<>();
        int at = 4;                                       // the protocol version
        while (at < body.length && body[at] != 0) {
            int nameEnd = indexOfNul(body, at);
            int valueEnd = indexOfNul(body, nameEnd + 1);
            found.add(new String[] {
                new String(body, at, nameEnd - at, StandardCharsets.UTF_8),
                new String(body, nameEnd + 1, valueEnd - nameEnd - 1, StandardCharsets.UTF_8)});
            at = valueEnd + 1;
        }
        assertEquals(body.length - 1, at, "the pairs end with one NUL, and the message there");
        return found;
    }

    private static int indexOfNul(byte[] body, int from) {
        for (int i = from; i < body.length; i++) {
            if (body[i] == 0) {
                return i;
            }
        }
        throw new AssertionError("no NUL after " + from);
    }

    private static byte[] startupMessage(String user, String database, String application)
            throws Exception {
        try (ServerSocket listener = new ServerSocket()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            listener.setSoTimeout(5000);
            CompletableFuture<byte[]> received = CompletableFuture.supplyAsync(() -> {
                try (Socket socket = listener.accept();
                     DataInputStream in = new DataInputStream(socket.getInputStream())) {
                    socket.setSoTimeout(5000);
                    int length = in.readInt();
                    byte[] body = new byte[length - 4];
                    in.readFully(body);
                    return body;                          // then hang up: no login
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            SeclumeDataSource source = new SeclumeDataSource();
            source.setHost("127.0.0.1");
            source.setPort(listener.getLocalPort());
            source.setTls("off");
            source.setSecretProvider(NoSecretProvider.INSTANCE);
            source.setConnectTimeoutMillis(3000);
            source.setUser(user);
            source.setDatabase(database);
            source.setApplicationName(application);
            assertThrows(java.sql.SQLException.class, () -> source.getConnection().close());
            return received.get(10, TimeUnit.SECONDS);
        }
    }

    @Test
    void theLoginFieldsComeFirstInOrderEachOnceAndAsSet() throws Exception {
        String application = "billing = 100% ü \"x\" user=postgres";
        byte[] body = startupMessage("app_user", "orders", application);
        assertEquals(0x00030000, ((body[0] & 0xff) << 24) | ((body[1] & 0xff) << 16)
                | ((body[2] & 0xff) << 8) | (body[3] & 0xff), "protocol 3.0");
        List<String[]> pairs = pairs(body);
        String[][] first = {{"user", "app_user"}, {"database", "orders"},
            {"application_name", application}, {"client_encoding", "UTF8"}};
        for (int i = 0; i < first.length; i++) {
            assertEquals(first[i][0], pairs.get(i)[0], "pair " + i);
            assertEquals(first[i][1], pairs.get(i)[1], first[i][0]);
        }
        HashSet<String> names = new HashSet<>();
        for (String[] pair : pairs) {
            assertTrue(names.add(pair[0]), pair[0] + " was sent twice");
        }
        assertTrue(pairs.stream().anyMatch(p -> p[0].equals("extra_float_digits")
                && p[1].equals("3")), "extra_float_digits=3");
    }
}
