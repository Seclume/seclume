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
 * JVM only ever learns the paths. For OAuth 2.0 it runs a token endpoint as
 * well, which issues one token, known in advance, to a client secret made up
 * here - and writes the secret, its form-encoded Basic credential and the
 * token to files the same way.
 *
 * <pre>
 * args: keystore  directory
 * out:  READY bearerPort basicPort headerPort tokenPort oauthApiPort
 *       (then it serves until stdin closes)
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
        String clientSecret = "cs-" + HexFormat.of().formatHex(random.generateSeed(16)) + "/+x";
        String tokenPrefix = "at-" + HexFormat.of().formatHex(random.generateSeed(16)) + "-";
        Files.writeString(directory.resolve("client-secret"), clientSecret);
        Files.writeString(directory.resolve("access-token"), tokenPrefix + "1");
        Files.writeString(directory.resolve("oauth-basic.b64"), Base64.getEncoder()
                .encodeToString(("app-1:" + clientSecret.replace("/", "%2F").replace("+", "%2B"))
                        .getBytes(StandardCharsets.US_ASCII)));

        SSLContext tls = TestPki.load(keystore).serverContext();
        try (FakeHttpsServer bearer = new FakeHttpsServer(tls);
             FakeHttpsServer basicServer = new FakeHttpsServer(tls);
             FakeHttpsServer header = new FakeHttpsServer(tls);
             FakeTokenServer tokens = new FakeTokenServer(tls);
             FakeHttpsServer oauthApi = new FakeHttpsServer(tls)) {
            tokens.clientSecret = clientSecret;
            tokens.tokenPrefix = tokenPrefix;
            oauthApi.accepts = tokens.valid::contains;
            bearer.expected = ("Bearer " + token).getBytes(StandardCharsets.US_ASCII);
            basicServer.expected = ("Basic " + basic).getBytes(StandardCharsets.US_ASCII);
            header.headerName = "X-Api-Key";
            header.expected = apiKey.getBytes(StandardCharsets.US_ASCII);
            System.out.println("READY " + bearer.port() + " " + basicServer.port() + " "
                    + header.port() + " " + tokens.port() + " " + oauthApi.port());
            System.out.flush();
            while (System.in.read() >= 0) {
                // serve until the test closes our stdin
            }
            int all = 0;
            int authorized = 0;
            for (FakeHttpsServer server : List.of(bearer, basicServer, header, oauthApi)) {
                all += server.received.size();
                authorized += (int) server.received.stream()
                        .filter(FakeHttpsServer.Received::authorized).count();
            }
            System.out.println("RECEIVED " + all + " AUTHORIZED " + authorized + " TOKENS "
                    + tokens.issued.get());
        }
    }
}
