package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.SessionContext;
import space.seclume.tck.TestHosts;

/**
 * Behind PgBouncer in transaction mode, with one server connection for all
 * clients - so that every client shares the same server session and anything
 * one of them leaves on it, the next one gets.
 *
 * <p>Needs a PgBouncer 1.21 or later ({@code max_prepared_statements} set,
 * {@code default_pool_size = 1}) in front of the TLS PostgreSQL:
 * {@code -Dseclume.pgbouncer.port} (and {@code .host}).
 */
class PgBouncerTest {

    private static String base;

    @BeforeAll
    static void findTheBouncer() throws Exception {
        int port = Integer.getInteger("seclume.pgbouncer.port", 0);
        Assumptions.assumeTrue(port > 0, "no PgBouncer configured (-Dseclume.pgbouncer.port)");
        String host = System.getProperty("seclume.pgbouncer.host", TestHosts.database());
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
        Path secret = TypeCatalogTest.locate(".local-pgtls-password");
        base = "jdbc:seclume:postgresql://" + host + ":" + port
                + "/seclume_test?user=seclume_test&tls=off&provider=file&path="
                + TypeCatalogTest.slash(secret);
    }

    @Test
    void preparedStatementsWorkAcrossClientsSharingOneServerSession() throws Exception {
        try (Connection a = DriverManager.getConnection(base + "&proxyMode=transaction");
             Connection b = DriverManager.getConnection(base + "&proxyMode=transaction");
             Connection c = DriverManager.getConnection(base + "&proxyMode=transaction")) {
            for (int i = 0; i < 20; i++) {
                for (Connection each : new Connection[] {a, b, c}) {
                    try (PreparedStatement s = each.prepareStatement("select ?::int + 1")) {
                        s.setInt(1, i);
                        try (ResultSet rows = s.executeQuery()) {
                            rows.next();
                            assertEquals(i + 1, rows.getInt(1));
                        }
                    }
                }
            }
        }
    }

    /** The control: without proxyMode the characteristics are the session's, and they leak. */
    @Test
    void withoutProxyModeReadOnlyReachesTheNextClient() throws Exception {
        try (Connection a = DriverManager.getConnection(base);
             Connection b = DriverManager.getConnection(base)) {
            a.setReadOnly(true);
            one(a, "select 1");
            try {
                assertEquals("on", one(b, "show transaction_read_only"),
                        "the leak this mode exists for did not happen - the test proves nothing");
            } finally {
                a.setReadOnly(false);
                one(a, "select 1");
            }
        }
    }

    @Test
    void withProxyModeTheCharacteristicsStayInTheOwnTransaction() throws Exception {
        try (Connection a = DriverManager.getConnection(base + "&proxyMode=transaction");
             Connection b = DriverManager.getConnection(base + "&proxyMode=transaction")) {
            a.setReadOnly(true);
            a.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            a.setAutoCommit(false);
            assertEquals("on", one(a, "show transaction_read_only"));
            assertEquals("serializable", one(a, "show transaction_isolation"));
            a.commit();
            assertEquals("off", one(b, "show transaction_read_only"));
            assertEquals("read committed", one(b, "show transaction_isolation"));

            // And the next transaction of the same client carries them again.
            assertEquals("on", one(a, "show transaction_read_only"));
            a.rollback();
            a.setAutoCommit(true);
            a.setReadOnly(false);
            a.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
        }
    }

    @Test
    void aSessionContextIsRefusedBehindATransactionPooler() throws Exception {
        try (Connection a = DriverManager.getConnection(base + "&proxyMode=transaction")) {
            assertThrows(java.sql.SQLFeatureNotSupportedException.class, () -> a.unwrap(
                    SessionContext.class).setSessionContext("app.tenant_id", "1"));
        }
    }

    private static String one(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement(); ResultSet rows = s.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
