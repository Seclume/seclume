package space.seclume.sqlserver.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * A token login (FEDAUTH) against a SQL Server that has no Microsoft Entra
 * configured: it cannot accept the token, but it has to understand the login
 * well enough to say so - a malformed feature list would end in a broken
 * connection or "the login packet is invalid" instead.
 */
@Timeout(60)
class LocalAccessTokenTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);

    @BeforeAll
    static void findTheServer() {
        boolean configured = false;
        for (Path candidate : List.of(Path.of(".local-mssql-password"),
                Path.of("..", ".local-mssql-password"))) {
            configured |= Files.exists(candidate);
        }
        Assumptions.assumeTrue(configured, "no .local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
    }

    @Test
    void theServerUnderstandsTheTokenLoginAndRefusesItAsALogin(@TempDir Path directory)
            throws Exception {
        Path token = directory.resolve("token");
        Files.writeString(token, "eyJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXN0In0.c2lnbmF0dXJl");
        // The token goes only to a server whose key is known: pinned here,
        // since the test server's certificate is self-signed.
        String url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?authentication=token&tlsPin=" + serverPin() + "&provider=file&path="
                + token.toString().replace(java.io.File.separatorChar, '/');
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url).close());
        // 18456 is "Login failed": the server read the feature list, found
        // a token and could not accept it - the answer of a server without
        // Entra, and a different one from a packet it could not parse.
        assertEquals(18456, refused.getErrorCode(), refused.getMessage());
        assertEquals("28000", refused.getSQLState(), refused.getMessage());
    }

    /** trustServerCertificate encrypts to anybody - no token goes there, and nothing is sent. */
    @Test
    void noTokenGoesToAnUncheckedServer(@TempDir Path directory) throws Exception {
        Path token = directory.resolve("token");
        Files.writeString(token, "eyJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXN0In0.c2lnbmF0dXJl");
        String url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?authentication=token&trustServerCertificate=true&provider=file&path="
                + token.toString().replace(java.io.File.separatorChar, '/');
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url).close());
        assertEquals("28000", refused.getSQLState(), refused.getMessage());
        assertEquals(true, refused.getMessage().contains("nothing was sent"), refused.getMessage());
    }

    private static String serverPin() throws Exception {
        return space.seclume.sqlserver.tds.ServerKey.pin(HOST, PORT);
    }
}
