package space.seclume.elasticsearch;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * {@link FakeHttpsServer} in a JVM of its own, for {@link NoKeyOnTheHeapTest}:
 * it makes the API key, writes it to {@code <dir>/es.key} and expects it, so
 * the test's JVM only ever holds the path. {@code READY <port>} when it
 * serves; when its input ends, {@code RECEIVED <n> AUTHORIZED <m>} and exit.
 *
 * <pre>SearchServerMain &lt;keystore&gt; &lt;dir&gt;</pre>
 */
public final class SearchServerMain {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SearchServerMain() {
    }

    public static void main(String[] args) throws Exception {
        TestPki pki = TestPki.load(Path.of(args[0]));
        byte[] random = new byte[30];
        RANDOM.nextBytes(random);
        String key = Base64.getEncoder().encodeToString(random);
        Files.writeString(Path.of(args[1]).resolve("es.key"), key);
        try (FakeHttpsServer server = new FakeHttpsServer(pki.serverContext())) {
            server.expected = ("ApiKey " + key).getBytes(StandardCharsets.UTF_8);
            System.out.println("READY " + server.port());
            System.out.flush();
            System.in.readAllBytes();
            long authorized = server.received.stream().filter(FakeHttpsServer.Received::authorized)
                    .count();
            System.out.println("RECEIVED " + server.received.size() + " AUTHORIZED " + authorized);
        }
    }
}
