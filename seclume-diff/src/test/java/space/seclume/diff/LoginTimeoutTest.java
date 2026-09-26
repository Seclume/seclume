package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.tck.TestHosts;

/**
 * connectTimeout bounds the whole login, not only the TCP connect. Found
 * against a real Aurora failover on 26.09.2026: an instance accepted the
 * connection and never answered the login, and a new connection waited for
 * as long as anybody let it. And the bound ends with the login - a statement
 * afterwards may take longer than it.
 */
class LoginTimeoutTest {

    /** A server that takes the connection and says nothing, ever. */
    @ParameterizedTest
    @ValueSource(strings = {"postgresql", "mysql", "sqlserver", "oracle"})
    void aServerThatNeverAnswersTheLoginIsGivenUp(String kind) throws Exception {
        try (ServerSocket silent = new ServerSocket()) {
            silent.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            Thread holder = Thread.ofVirtual().start(() -> {
                try (Socket accepted = silent.accept()) {
                    accepted.getInputStream().readAllBytes();   // until the client gives up
                } catch (IOException gone) {
                    // the client closed: done
                }
            });
            String url = "jdbc:seclume:" + kind + "://127.0.0.1:" + silent.getLocalPort()
                    + "/db?user=u&provider=none&connectTimeout=1000";
            long start = System.nanoTime();
            assertThrows(SQLException.class, () -> DriverManager.getConnection(url).close());
            long millis = (System.nanoTime() - start) / 1_000_000;
            assertTrue(millis < 5000, kind + " waited " + millis + " ms for a silent server");
            holder.join(5000);
        }
    }

    /** After the login the bound is gone: a statement slower than it still finishes. */
    @Test
    void theBoundEndsWithTheLogin() throws Exception {
        int ran = 0;
        for (String[] db : List.of(
                new String[] {TestHosts.postgresPasswordFile(), TestHosts.postgres(),
                        String.valueOf(TestHosts.postgresPort()),
                        "jdbc:seclume:postgresql://%s:%s/seclume_test?user=seclume_test&tls=off",
                        "select pg_sleep(2)"},
                new String[] {".local-mysql-password", TestHosts.database(), "3307",
                        "jdbc:seclume:mysql://%s:%s/seclume_test?user=seclume_test&tls=off"
                                + "&allowPublicKeyRetrieval=true", "select sleep(2)"},
                new String[] {".local-mssql-password", TestHosts.database(), "1433",
                        "jdbc:seclume:sqlserver://%s:%s/master?user=sa"
                                + "&trustServerCertificate=true", "waitfor delay '00:00:02'"},
                new String[] {".local-oracle-password", TestHosts.database(), "1521",
                        "jdbc:seclume:oracle://%s:%s/FREEPDB1?user=seclume_test",
                        "begin dbms_session.sleep(2); end;"})) {
            Path secret = TypeCatalogTest.locate(db[0]);
            if (secret == null || !reachable(db[1], Integer.parseInt(db[2]))) {
                continue;
            }
            String url = db[3].formatted(db[1], db[2]) + "&connectTimeout=1000"
                    + "&provider=file&path=" + TypeCatalogTest.slash(secret);
            try (Connection connection = DriverManager.getConnection(url);
                 Statement statement = connection.createStatement()) {
                statement.execute(db[4]);          // two seconds against a one-second bound
            }
            ran++;
        }
        org.junit.jupiter.api.Assumptions.assumeTrue(ran > 0, "no database reachable");
    }

    private static boolean reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
            return true;
        } catch (IOException unreachable) {
            return false;
        }
    }
}
