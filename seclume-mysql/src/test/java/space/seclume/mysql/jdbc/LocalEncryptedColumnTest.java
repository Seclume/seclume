package space.seclume.mysql.jdbc;

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
 * Field encryption on MySQL: {@link EncryptedColumnContract} - ciphertext
 * only on the server, a deterministic column searched through a unique
 * index, a rotation in use, a heap dump without the value or the key.
 */
@Timeout(600)
@org.junit.jupiter.api.parallel.Isolated
class LocalEncryptedColumnTest extends EncryptedColumnContract {

    private static final String HOST =
            System.getProperty("seclume.mysql.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"), Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + ".local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/seclume_test"
                + "?user=seclume_test&allowPublicKeyRetrieval=true&provider=file&path="
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
