package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import space.seclume.tck.TestHosts;

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
import javax.transaction.xa.XAException;
import javax.transaction.xa.XAResource;
import javax.transaction.xa.Xid;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.XidText;

/**
 * Distributed transactions against the real server.
 *
 * <p>One-phase always works. The two-phase part needs
 * {@code max_prepared_transactions} greater than zero on the server, and that
 * is not this test's business to change - it is a setting with a cost, and
 * turning it on means a restart. So when the server refuses, the two-phase
 * test says why it is skipped instead of failing.
 */
class LocalXaTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static Path password;

    @BeforeAll
    static void findTheServer() {
        password = locatePasswordFile();
        Assumptions.assumeTrue(password != null,
                "no " + TestHosts.postgresPasswordFile() + " - skipping the tests "
                        + "against a real server");
        Assumptions.assumeTrue(reachable(), "no PostgreSQL on "
                + TestHosts.postgres() + ":" + TestHosts.postgresPort());
    }

    private static SeclumeXaDataSource source() {
        SeclumeXaDataSource source = new SeclumeXaDataSource();
        SeclumeDataSource settings = source.settings();
        settings.setHost(TestHosts.postgres());
        settings.setPort(TestHosts.postgresPort());
        settings.setDatabase(DATABASE);
        settings.setUser(USER);
        settings.setProperty("provider", "file");
        settings.setProperty("path", password.toString().replace('\\', '/'));
        return source;
    }

    /** Format id, one global id, one branch - what a manager would hand out. */
    private static Xid xid(String suffix) {
        return new XidText.Recovered(0x7a10,
                ("seclume-" + suffix).getBytes(StandardCharsets.US_ASCII),
                new byte[] {1, 2, 3});
    }

    @Test
    void onePhaseCommitWritesTheRow() throws Exception {
        String table = "xa_one_" + System.nanoTime();
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
        String table = "xa_back_" + System.nanoTime();
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

    /**
     * The real thing: prepare on one connection, commit on another. That is
     * what survives a crash of the application, and nothing less counts.
     */
    @Test
    void aPreparedTransactionIsFinishedByAnotherConnection() throws Exception {
        String table = "xa_two_" + System.nanoTime();
        Xid xid = xid("two");
        XAConnection first = source().getXAConnection();
        try {
            XAResource resource = first.getXAResource();
            Connection connection = first.getConnection();
            create(connection, table);
            resource.start(xid, XAResource.TMNOFLAGS);
            insert(connection, table, 42);
            resource.end(xid, XAResource.TMSUCCESS);
            assumePreparedTransactions(resource, xid);
            assertEquals(0, count(connection, table), "not visible before the commit");
        } finally {
            first.close();
        }
        XAConnection second = source().getXAConnection();
        try {
            XAResource resource = second.getXAResource();
            Connection connection = second.getConnection();
            assertTrue(contains(resource.recover(XAResource.TMSTARTRSCAN), xid),
                    "recover has to find what was prepared");
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
                 ResultSet rows = statement.executeQuery("select 1")) {
                assertTrue(rows.next());
            }
        } finally {
            xa.close();
        }
    }

    private static void assumePreparedTransactions(XAResource resource, Xid xid) throws Exception {
        try {
            resource.prepare(xid);
        } catch (XAException e) {
            String message = e.getMessage() == null ? "" : e.getMessage();
            Assumptions.assumeFalse(message.contains("max_prepared_transactions"),
                    "max_prepared_transactions is 0 on this server - no two-phase commit");
            throw e;
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
        run(connection, "create table " + table + " (n int)");
    }

    private static void drop(Connection connection, String table) throws SQLException {
        run(connection, "drop table if exists " + table);
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

    private static Path locatePasswordFile() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static boolean reachable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 1000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
