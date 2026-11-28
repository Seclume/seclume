package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.secret.NoSecretProvider;

/**
 * A NUL in the user, the database or the application name would end that
 * field in the StartupMessage early and start the next one with what
 * follows - "app\0replication\0database" names a field the application never
 * set. Refused before a byte is sent: the server's socket sees nothing.
 */
class NulInStartupFieldsTest {

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"user", "database", "applicationName"})
    void aNulIsRefusedBeforeTheStartupMessage(String field) throws Exception {
        try (ServerSocket listener = new ServerSocket()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            listener.setSoTimeout(5000);
            CompletableFuture<Integer> received = CompletableFuture.supplyAsync(() -> {
                try (Socket socket = listener.accept(); InputStream in = socket.getInputStream()) {
                    socket.setSoTimeout(2000);
                    int count = 0;
                    try {
                        while (in.read() >= 0) {
                            count++;
                        }
                    } catch (java.net.SocketTimeoutException quiet) {
                        // nothing more came
                    }
                    return count;
                } catch (IOException nobodyCame) {
                    return 0;
                }
            });
            SeclumeDataSource source = new SeclumeDataSource();
            source.setHost("127.0.0.1");
            source.setPort(listener.getLocalPort());
            source.setTls("off");
            source.setSecretProvider(NoSecretProvider.INSTANCE);
            source.setConnectTimeoutMillis(3000);
            source.setUser(field.equals("user") ? "app\0replication" : "app");
            source.setDatabase(field.equals("database") ? "app\0options" : "app");
            if (field.equals("applicationName")) {
                source.setApplicationName("report\0replication");
            }
            SQLException refused = assertThrows(SQLException.class,
                    () -> source.getConnection().close());
            assertEquals(0, received.get(10, TimeUnit.SECONDS),
                    "bytes reached the server for " + field + ": " + refused.getMessage());
        }
    }
}
