package space.seclume.http;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

/**
 * An HTTPS API in a process of its own that knows the secrets - read from the
 * files a shell wrote - and says for each request whether its credential was
 * the right one. The body is echoed back, so a test sees it arrived as sent.
 */
public final class CredentialServerProcess {

    private CredentialServerProcess() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        String token = Files.readString(directory.resolve("token")).trim();
        String password = Files.readString(directory.resolve("password")).trim();
        java.security.KeyStore keys = java.security.KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(directory.resolve("store.p12"))) {
            keys.load(in, "store".toCharArray());
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance("PKIX");
        factory.init(keys, "store".toCharArray());
        SSLContext tls = SSLContext.getInstance("TLSv1.3");
        tls.init(factory.getKeyManagers(), null, null);
        HttpsServer server = HttpsServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        server.createContext("/", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            String authorization = String.valueOf(exchange.getRequestHeaders()
                    .getFirst("Authorization"));
            String apiKey = String.valueOf(exchange.getRequestHeaders().getFirst("X-Api-Key"));
            boolean ok = switch (exchange.getRequestURI().getPath()) {
                case "/bearer" -> authorization.equals("Bearer " + token);
                case "/api-key" -> apiKey.equals(token);
                case "/basic" -> authorization.equals("Basic " + Base64.getEncoder()
                        .encodeToString(("deploy:" + password).getBytes(StandardCharsets.UTF_8)));
                default -> false;
            };
            byte[] answer = ((ok ? "ok " : "refused ") + new String(body, StandardCharsets.UTF_8))
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(ok ? 200 : 401, answer.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(answer);
            }
        });
        server.start();
        Files.writeString(directory.resolve("port.tmp"), String.valueOf(server.getAddress()
                .getPort()));
        Files.move(directory.resolve("port.tmp"), directory.resolve("port"));
        Thread.sleep(Long.MAX_VALUE);
    }
}
