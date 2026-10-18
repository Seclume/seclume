package space.seclume.mongospring;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Assumptions;

import space.seclume.tck.TestHosts;

/** Where the MongoDB fixtures are, and their URLs; a test without them is skipped. */
final class Fixture {

    static final String HOST = System.getProperty("seclume.mongo.host", TestHosts.database());

    private Fixture() {
    }

    static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    static Path password() {
        return find(".local-mongo-password");
    }

    static boolean reachable(int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, port), 2000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** The standalone server, or {@code null}. */
    static String standalone() {
        Path ca = find(".local-mongo-ca.pem");
        if (password() == null || ca == null || !reachable(27017)) {
            return null;
        }
        return url(HOST + ":27017", ca, "");
    }

    /** The replica set, or {@code null}. */
    static String replicaSet() {
        Path ca = find(".local-mongo-rs-ca.pem");
        if (password() == null || ca == null || !reachable(27021) || !reachable(27022)
                || !reachable(27023)) {
            return null;
        }
        return url(HOST + ":27021," + HOST + ":27022," + HOST + ":27023", ca,
                "&replicaSet=slm-rs");
    }

    static void assumeThere(String url, String what) {
        Assumptions.assumeTrue(url != null, "no MongoDB " + what);
    }

    private static String url(String hosts, Path ca, String more) {
        return "mongodb://seclume_test@" + hosts + "/?authSource=admin&provider=file&path="
                + password().toString().replace('\\', '/')
                + "&tlsRootCert=" + ca.toString().replace('\\', '/') + more;
    }
}
