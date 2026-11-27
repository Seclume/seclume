package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.CountDownLatch;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.secret.CallbackSecretProvider;

/**
 * An UPDATE in auto-commit whose answer never comes, and whose cancel the
 * server ignores: whether it was applied is unknown. The caller is told so -
 * 08007, a TransactionResolutionUnknownException, never a plain timeout a
 * retry would repeat the write after - and the connection, whose state is
 * unknown too, is not used again.
 */
@Timeout(60)
class KilledWriteInDoubtTest {

    private static final String USER = "app";
    private static final String PASSWORD = "in-doubt-pw";

    @Test
    void aWriteWhoseAnswerNeverComesIsInDoubtAndTheConnectionGoes() throws Exception {
        CountDownLatch never = new CountDownLatch(1);
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.start();
            space.seclume.mysql.jdbc.MyDataSource source = new space.seclume.mysql.jdbc.MyDataSource();
            source.setHost("127.0.0.1");
            source.setPort(server.port());
            source.setDatabase("testdb");
            source.setUser(USER);
            source.setAllowLegacyHashOverUnverifiedTls(true);     // the stand-in: native, no TLS
            byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
            source.setSecretProvider(new CallbackSecretProvider(64, target -> {
                for (int i = 0; i < bytes.length; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
                }
                return bytes.length;
            }));
            try (Connection connection = source.getConnection();
                 Statement statement = connection.createStatement()) {
                server.holdQueriesUntil(never);          // every statement from now on, the KILL too
                statement.setQueryTimeout(1);
                SQLException failed = assertThrows(SQLException.class,
                        () -> statement.executeUpdate("update accounts set balance = balance - 10"));
                assertEquals("08007", failed.getSQLState(), failed.toString());
                assertTrue(failed instanceof space.seclume.TransactionResolutionUnknownException,
                        failed.getClass().getName());
                assertFalse(connection.isValid(1), "a connection in an unknown state is used again");
            } finally {
                never.countDown();
            }
        }
    }
}
