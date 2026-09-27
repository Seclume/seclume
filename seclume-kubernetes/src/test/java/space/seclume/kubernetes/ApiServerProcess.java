package space.seclume.kubernetes;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

/**
 * Just enough of a Kubernetes API server, in a process of its own: it reads the
 * current token from the file for each request - the way a rotated token is
 * valid at once - and lists one pod to whoever presents it.
 */
public final class ApiServerProcess {

    private ApiServerProcess() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
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
            String token = Files.readString(directory.resolve("token")).trim();
            boolean ok = ("Bearer " + token).equals(exchange.getRequestHeaders()
                    .getFirst("Authorization"));
            byte[] body = (ok ? "{\"kind\":\"PodList\",\"apiVersion\":\"v1\",\"metadata\":{},"
                    + "\"items\":[{\"metadata\":{\"name\":\"web-1\",\"namespace\":\"default\"}}]}"
                    : "{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"status\":\"Failure\","
                    + "\"reason\":\"Unauthorized\",\"code\":401}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(ok ? 200 : 401, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        Files.writeString(directory.resolve("port.tmp"), String.valueOf(server.getAddress()
                .getPort()));
        Files.move(directory.resolve("port.tmp"), directory.resolve("port"));
        Thread.sleep(Long.MAX_VALUE);
    }
}
