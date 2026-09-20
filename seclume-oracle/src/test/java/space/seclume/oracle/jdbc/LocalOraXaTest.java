package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import javax.sql.XAConnection;
import javax.transaction.xa.XAResource;
import javax.transaction.xa.Xid;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.XidText;

/**
 * Distributed transactions against a real Oracle.
 *
 * <p>What has to be proven here is that {@code DBMS_XA} is driven correctly -
 * the package answers with a return code and never raises by itself, so a
 * driver that does not look at the code would report success for a branch that
 * was never opened.
 */
class LocalOraXaTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    /** One run's own ids - a left-over branch must not block the next run. */
    private static final String RUN = Long.toHexString(System.nanoTime());

    private static Path password;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
    }

    /** Leaves the schema as it was found - see {@link OracleTestSchema}. */
    @AfterAll
    static void cleanUp() throws Exception {
        javax.sql.XAConnection xa;
        try {
            xa = source().getXAConnection();
        } catch (Exception e) {
            return;                                    // no server, nothing to clean
        }
        try (java.sql.Connection connection = xa.getConnection()) {
            OracleTestSchema.clean(connection);
        } finally {
            xa.close();
        }
    }

    private static OraXaDataSource source() {
        OraXaDataSource source = new OraXaDataSource();
        OraDataSource settings = source.settings();
        settings.setHost(HOST);
        settings.setPort(PORT);
        settings.setService(SERVICE);
        settings.setUser(USER);
        settings.setProperty("provider", "file");
        settings.setProperty("path", password.toString().replace('\\', '/'));
        return source;
    }

    private static Xid xid(String suffix) {
        byte[] global = ("zl-" + RUN + "-" + suffix).getBytes(StandardCharsets.US_ASCII);
        return new XidText.Recovered(0x7a10, global, new byte[] {0, 1, (byte) 0xff, 0x2a});
    }

    @Test
    void onePhaseCommitWritesTheRow() throws Exception {
        String table = "xa_one_" + RUN;
        XAConnection xa = source().getXAConnection();
        try {
            XAResource resource = xa.getXAResource();
            Connection connection = xa.getConnection();
            create(connection, table);
            Xid xid = xid("one");
            resource.start(xid, XAResource.TMNOFLAGS);
            insert(connection, table, 1);
            resource.end(xid, XAResource.TMSUCCESS);
            resource.commit(xid, true);
            assertEquals(1, count(connection, table));
            drop(connection, table);
        } finally {
            xa.close();
        }
    }

    @Test
    void aRollbackLeavesNothingBehind() throws Exception {
        String table = "xa_back_" + RUN;
        XAConnection xa = source().getXAConnection();
        try {
            XAResource resource = xa.getXAResource();
            Connection connection = xa.getConnection();
            create(connection, table);
            Xid xid = xid("back");
            resource.start(xid, XAResource.TMNOFLAGS);
            insert(connection, table, 7);
            resource.end(xid, XAResource.TMSUCCESS);
            resource.rollback(xid);
            assertEquals(0, count(connection, table));
            drop(connection, table);
        } finally {
            xa.close();
        }
    }

    /** Prepare on one connection, commit on another - the whole point. */
    @Test
    void aPreparedTransactionIsFinishedByAnotherConnection() throws Exception {
        String table = "xa_two_" + RUN;
        Xid xid = xid("two");
        XAConnection first = source().getXAConnection();
        try {
            XAResource resource = first.getXAResource();
            Connection connection = first.getConnection();
            create(connection, table);
            resource.start(xid, XAResource.TMNOFLAGS);
            insert(connection, table, 42);
            resource.end(xid, XAResource.TMSUCCESS);
            resource.prepare(xid);
        } finally {
            first.close();
        }
        XAConnection second = source().getXAConnection();
        try {
            XAResource resource = second.getXAResource();
            Connection connection = second.getConnection();
            assertEquals(0, count(connection, table), "not visible before the commit");
            assertTrue(contains(resource.recover(XAResource.TMSTARTRSCAN), xid),
                    "recover has to find what was prepared, byte for byte");
            resource.commit(xid, false);
            assertFalse(contains(resource.recover(XAResource.TMSTARTRSCAN), xid),
                    "and not find it any more afterwards");
            assertEquals(1, count(connection, table));
            drop(connection, table);
        } finally {
            second.close();
        }
    }

    /** The handle is given back, the session stays - that is the JTA contract. */
    @Test
    void closingTheHandleDoesNotCloseTheSession() throws Exception {
        XAConnection xa = source().getXAConnection();
        try {
            Connection handle = xa.getConnection();
            handle.close();
            assertTrue(handle.isClosed());
            try (Connection again = xa.getConnection();
                 Statement statement = again.createStatement();
                 ResultSet rows = statement.executeQuery("select 1 from dual")) {
                assertTrue(rows.next());
            }
        } finally {
            xa.close();
        }
    }

    private static boolean contains(Xid[] found, Xid wanted) {
        for (Xid one : found) {
            if (XidText.of(one).equals(XidText.of(wanted))) {
                return true;
            }
        }
        return false;
    }

    private static void create(Connection connection, String table) throws SQLException {
        drop(connection, table);
        run(connection, "create table " + table + " (n number)");
    }

    private static void drop(Connection connection, String table) {
        try {
            run(connection, "drop table " + table + " purge");   // purge: Oracle keeps counting it otherwise
        } catch (SQLException e) {
            // ORA-00942, it was not there - which is what was wanted.
        }
    }

    private static void insert(Connection connection, String table, int value) throws SQLException {
        run(connection, "insert into " + table + " values (" + value + ")");
    }

    private static void run(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static int count(Connection connection, String table) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select count(*) from " + table)) {
            rows.next();
            return rows.getInt(1);
        }
    }
}
