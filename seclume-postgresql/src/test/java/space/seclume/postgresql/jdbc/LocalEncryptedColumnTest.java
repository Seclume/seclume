package space.seclume.postgresql.jdbc;

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
 * Field encryption on PostgreSQL: {@link EncryptedColumnContract} - ciphertext
 * only on the server, a deterministic column searched through a unique
 * index, a rotation in use, a heap dump without the value or the key.
 */
@Timeout(600)
@org.junit.jupiter.api.parallel.Isolated
class LocalEncryptedColumnTest extends EncryptedColumnContract {

    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(space.seclume.tck.TestHosts.postgresPasswordFile()), Path.of("..", space.seclume.tck.TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + space.seclume.tck.TestHosts.postgresPasswordFile());
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(space.seclume.tck.TestHosts.postgres(), space.seclume.tck.TestHosts.postgresPort()), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + space.seclume.tck.TestHosts.postgres() + ":" + space.seclume.tck.TestHosts.postgresPort());
        }
        url = "jdbc:seclume:postgresql://" + space.seclume.tck.TestHosts.postgres() + ":"
                + space.seclume.tck.TestHosts.postgresPort()
                + "/seclume_test?user=seclume_test&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    @Override
    protected String url() {
        return url;
    }

    @Override
    protected String binary(int length) {
        return "bytea";
    }
}
