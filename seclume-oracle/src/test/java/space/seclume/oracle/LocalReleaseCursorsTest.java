package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.SecretProviders;

/**
 * Giving cursors back must not end the transaction.
 *
 * <p>{@code releaseCursors()} is what a session calls before it is handed
 * over with {@code detach()}. Returning a cursor is a piggyback and needs a
 * call to ride on, and the call it rode on was a <b>rollback</b> - chosen as
 * the one call that opens no cursor of its own. It also ended the transaction
 * the session was in: every session detached with an uncommitted row lost it,
 * and nothing said so. The hand-overs before had all been made between
 * transactions. It rides on a ping now, which changes nothing on the server.
 */
@Timeout(60)
class LocalReleaseCursorsTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String SERVICE = System.getProperty("seclume.oracle.service", "FREEPDB1");

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

    private static OracleSession open() throws Exception {
        return OracleSession.open(new OracleSession.Settings(HOST, PORT, SERVICE, "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", password.toString())),
                5_000, HostList.of(HOST, PORT), ResultLimit.NONE, TlsMode.OFF));
    }

    @Test
    void anOpenTransactionSurvivesGivingTheCursorsBack() throws Exception {
        try (OracleSession session = open()) {
            session.query("begin execute immediate 'drop table zl_release_cursors purge'; "
                    + "exception when others then null; end;", row -> { });
            session.query("create table zl_release_cursors (n number)", row -> { });
            try {
                session.setAutoCommit(false);
                session.query("insert into zl_release_cursors values (1)", row -> { });
                String transaction = session.askOneValue(
                        "select dbms_transaction.local_transaction_id from dual");
                assertNotNull(transaction, "the insert did not open a transaction");
                session.askOneValue("select count(*) from zl_release_cursors");

                session.releaseCursors();

                assertEquals(transaction, session.askOneValue(
                        "select dbms_transaction.local_transaction_id from dual"),
                        "giving the cursors back ended the transaction");
                assertEquals("1", session.askOneValue("select count(*) from zl_release_cursors"),
                        "the uncommitted row is gone - it was rolled back");
                try (OracleSession other = open()) {
                    assertEquals("0", other.askOneValue(
                            "select count(*) from zl_release_cursors"),
                            "the row was committed instead of kept open");
                }
                session.rollback();
            } finally {
                session.setAutoCommit(true);
                session.query("drop table zl_release_cursors purge", row -> { });
            }
        }
    }
}
