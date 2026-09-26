package space.seclume.postgresql.jdbc;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;
import space.seclume.tck.misuse.MisuseContract;

/**
 * JDBC called in the wrong order, against a real PostgreSQL.
 *
 * <p>The contract and the reasoning are in {@link MisuseContract}. Against a
 * real server rather than a script on purpose: the requirement that matters
 * is that the <b>connection still works afterwards</b>, and a fake server
 * cannot tell whether the stream is still in step - it answers whatever the
 * script says next either way.
 */
@Timeout(300)
class LocalMisuseTest {

    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null,
                "no " + TestHosts.postgresPasswordFile());
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres()
                    + ":" + TestHosts.postgresPort());
        }
        url = "jdbc:seclume:postgresql://" + TestHosts.postgres()
                + ":" + TestHosts.postgresPort() + "/" + DATABASE
                + "?user=" + USER + "&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static Connection connect() throws java.sql.SQLException {
        return DriverManager.getConnection(url);
    }

    @Test
    void everyCallOutOfOrderIsRefusedTheWayJdbcRefuses() {
        MisuseContract.check("postgresql", LocalMisuseTest::connect, "select 1",
                MisuseContract.standard("select 1",
                        "select n from (values (1), (2)) as t(n)",
                        "select 1 where 1 = ?"));
    }
}
