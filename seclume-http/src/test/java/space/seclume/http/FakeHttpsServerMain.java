package space.seclume.http;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import javax.net.ssl.SSLContext;

/**
 * Three {@link FakeHttpsServer}s in a JVM of their own, for the heap proof:
 * one expecting a bearer token, one Basic, one an API key in a header of its
 * own.
 *
 * <p>The servers have to know the secrets to check them, and a JVM that knows
 * them has them on its heap. So this process makes them up and writes them to
 * files for the client to read through its provider - and writes, next to
 * them, the Basic credential's base64, the form it takes on the wire. The test
 * JVM only ever learns the paths.
 *
 * <pre>
 * args: keystore  directory
 * out:  READY bearerPort basicPort headerPort   (then it serves until stdin closes)
 * </pre>
 */
public final class FakeHttpsServerMain {

    private FakeHttpsServerMain() {
    }

    public static void main(String[] args) throws Exception {
        Path keystore = Path.of(args[0]);
        Path directory = Path.of(args[1]);
        SecureRandom random = new SecureRandom();
        String token = "tok-" + HexFormat.of().formatHex(random.generateSeed(24));
        String password = "pw-" + HexFormat.of().formatHex(random.generateSeed(12));
        String apiKey = "key-" + HexFormat.of().formatHex(random.generateSeed(16));
        String basic = Base64.getEncoder().encodeToString(
                ("deploy:" + password).getBytes(StandardCharsets.US_ASCII));

        Files.writeString(directory.resolve("token"), token);
        Files.writeString(directory.resolve("password"), password);
        Files.writeString(directory.resolve("api-key"), apiKey);
        Files.writeString(directory.resolve("basic.b64"), basic);

        SSLContext tls = TestPki.load(keystore).serverContext();
        try (FakeHttpsServer bearer = new FakeHttpsServer(tls);
             FakeHttpsServer basicServer = new FakeHttpsServer(tls);
             FakeHttpsServer header = new FakeHttpsServer(tls)) {
            bearer.expected = ("Bearer " + token).getBytes(StandardCharsets.US_ASCII);
            basicServer.expected = ("Basic " + basic).getBytes(StandardCharsets.US_ASCII);
            header.headerName = "X-Api-Key";
            header.expected = apiKey.getBytes(StandardCharsets.US_ASCII);
            System.out.println("READY " + bearer.port() + " " + basicServer.port() + " "
                    + header.port());
            System.out.flush();
            while (System.in.read() >= 0) {
                // serve until the test closes our stdin
            }
            int all = 0;
            int authorized = 0;
            for (FakeHttpsServer server : List.of(bearer, basicServer, header)) {
                all += server.received.size();
                authorized += (int) server.received.stream()
                        .filter(FakeHttpsServer.Received::authorized).count();
            }
            System.out.println("RECEIVED " + all + " AUTHORIZED " + authorized);
        }
    }
}
