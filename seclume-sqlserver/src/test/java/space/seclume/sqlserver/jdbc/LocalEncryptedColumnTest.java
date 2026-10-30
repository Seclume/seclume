package space.seclume.sqlserver.jdbc;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.EncryptedColumnContract;

/**
 * Field encryption on SQL Server: {@link EncryptedColumnContract} - ciphertext
 * only on the server, a deterministic column searched through a unique
 * index, a rotation in use, a heap dump without the value or the key.
 */
@Timeout(600)
@org.junit.jupiter.api.parallel.Isolated
class LocalEncryptedColumnTest extends EncryptedColumnContract {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mssql-password"), Path.of("..", ".local-mssql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + ".local-mssql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:sqlserver://" + HOST + ":" + PORT + "/master"
                + "?user=sa&trustServerCertificate=true&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Override
    protected String url() {
        return url;
    }

    @Override
    protected String binary(int length) {
        return "varbinary(" + length + ")";
    }
}
