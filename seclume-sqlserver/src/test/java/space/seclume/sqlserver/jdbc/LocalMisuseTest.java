package space.seclume.sqlserver.jdbc;

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
 * JDBC called in the wrong order, against a real SQL Server.
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
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);
    private static final String USER = "sa";

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=" + USER + "&trustServerCertificate=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }

    @Test
    void everyCallOutOfOrderIsRefusedTheWayJdbcRefuses() {
        MisuseContract.check("sqlserver", LocalMisuseTest::connect, "select 1",
                MisuseContract.standard("select 1",
                        "select 1 as n union all select 2",
                        "select 1 where 1 = ?"));
    }
}
