package space.seclume.springtest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Assumptions;

/**
 * Finds the servers these tests need - or skips them.
 *
 * <p>The password file is the same one the driver tests use, and it is never
 * read here: its <b>path</b> goes into the configuration, and the driver
 * fetches the secret from it straight into native memory. That is the whole
 * point of the library, and it holds in the test setup too.
 */
final class Servers {

    private Servers() {
    }

    /**
     * Points the configuration at the password file and checks the server.
     *
     * @param file the name of the local password file, without a path
     * @param host where the server should be
     * @param port and on which port
     */
    static void require(String file, String host, int port) {
        Path password = null;
        for (Path candidate : List.of(Path.of(file), Path.of("..", file))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + file + " - skipping");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("no server on " + host + ":" + port);
        }
        System.setProperty("seclume.test.password.file",
                password.toString().replace('\\', '/'));
    }
}
