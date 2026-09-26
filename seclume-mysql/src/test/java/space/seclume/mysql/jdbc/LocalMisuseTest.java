package space.seclume.mysql.jdbc;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.misuse.MisuseContract;

/**
 * JDBC called in the wrong order, against a real MySQL.
 *
 * <p>The contract and the reasoning are in {@link MisuseContract}. Against a
 * real server rather than a script on purpose: the requirement that matters
 * is that the <b>connection still works afterwards</b>, and a fake server
 * cannot tell whether the stream is still in step - it answers whatever the
 * script says next either way.
 */
@Timeout(300)
class LocalMisuseTest {

    private static final String HOST =
            System.getProperty("seclume.mysql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);
    private static final String USER = "seclume_test";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test"
                + "?user=" + USER + "&allowPublicKeyRetrieval=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }

    @Test
    void everyCallOutOfOrderIsRefusedTheWayJdbcRefuses() {
        MisuseContract.check("mysql", LocalMisuseTest::connect, "select 1",
                MisuseContract.standard("select 1",
                        "select 1 as n from dual union all select 2 from dual",
                        "select 1 from dual where 1 = ?"));
    }
}
