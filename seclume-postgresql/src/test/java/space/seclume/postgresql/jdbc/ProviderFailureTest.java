package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * A secret provider that fails at the login - its file not there, Vault not
 * reachable - is an SQLException 08001 with the provider's failure as its
 * cause. It used to leave DriverManager.getConnection unchecked, past every
 * pool and retry that catches SQLException.
 */
class ProviderFailureTest {

    @Test
    void aProviderThatFailsAtTheLoginIsAnSqlException() {
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + host);
        }
        String url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=require&provider=file&path=/no/such/secret-file";
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url).close());
        assertEquals("08001", refused.getSQLState(), String.valueOf(refused));
        assertNotNull(refused.getCause(), "the provider's failure is the cause");
    }

    @Test
    void anUncheckedFailureBecomesOneSqlExceptionWithItsCause() {
        IllegalStateException cause = new IllegalStateException("vault: no route to host");
        SQLException refused = assertThrows(SQLException.class,
                () -> space.seclume.internal.jdbc.ConnectFailures.translated(() -> {
                    throw cause;
                }));
        assertEquals("08001", refused.getSQLState());
        assertEquals(cause, refused.getCause());
    }
}
