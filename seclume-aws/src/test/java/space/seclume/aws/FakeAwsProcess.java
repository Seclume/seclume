package space.seclume.aws;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

/**
 * AWS in a process of its own: a container credentials endpoint, STS and S3,
 * handing out and checking one set of temporary credentials. All the secrets
 * are here - read from the files a shell wrote - and none in the test's JVM.
 *
 * <p>{@code java FakeAwsProcess <directory>}: reads {@code store.p12},
 * {@code access-key-id}, {@code secret-key}, {@code session-token},
 * {@code container-token} and {@code web-identity-token} from there, writes
 * {@code ports} ("s3 sts container") once it listens, and appends every
 * refused request to {@code rejected}.
 */
public final class FakeAwsProcess {

    private FakeAwsProcess() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        String accessKeyId = read(directory, "access-key-id");
        String secretKey = read(directory, "secret-key");
        String token = read(directory, "session-token");
        String containerToken = read(directory, "container-token");
        String webIdentity = read(directory, "web-identity-token");
        Path rejected = directory.resolve("rejected");
        Files.writeString(rejected, "");

        SSLContext tls = tls(directory.resolve("store.p12"));
        FakeAws s3 = new FakeAws(() -> secretKey, tls);
        s3.sessionToken = () -> token;

        String credentialsJson = "{\"AccessKeyId\":\"" + accessKeyId + "\",\"SecretAccessKey\":\""
                + secretKey + "\",\"Token\":\"" + token + "\",\"Expiration\":\""
                + Instant.now().plusSeconds(3600) + "\"}";
        HttpServer container = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        container.createContext("/", exchange -> {
            boolean ok = containerToken.equals(exchange.getRequestHeaders().getFirst("Authorization"));
            if (!ok) {
                reject(rejected, "container: wrong authorization token");
            }
            respond(exchange, ok ? 200 : 403, ok ? credentialsJson : "{}");
        });
        container.start();

        HttpsServer sts = HttpsServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        sts.setHttpsConfigurator(new HttpsConfigurator(tls));
        sts.createContext("/", exchange -> {
            String form = new String(exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8);
            boolean ok = form.contains("Action=AssumeRoleWithWebIdentity")
                    && form.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fapp")
                    && form.contains("&WebIdentityToken=" + webIdentity);
            if (!ok) {
                reject(rejected, "sts: not the web identity token issued");
            }
            respond(exchange, ok ? 200 : 403, ok ? "<AssumeRoleWithWebIdentityResponse><Assume"
                    + "RoleWithWebIdentityResult><Credentials><AccessKeyId>" + accessKeyId
                    + "</AccessKeyId><SecretAccessKey>" + secretKey + "</SecretAccessKey>"
                    + "<SessionToken>" + token + "</SessionToken><Expiration>"
                    + Instant.now().plusSeconds(3600) + "</Expiration></Credentials></Assume"
                    + "RoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
                    : "<Error/>");
        });
        sts.start();

        Files.writeString(directory.resolve("ports.tmp"), s3.endpoint().getPort() + " "
                + sts.getAddress().getPort() + " " + container.getAddress().getPort());
        Files.move(directory.resolve("ports.tmp"), directory.resolve("ports"));
        while (true) {
            Thread.sleep(200);
            for (String problem : s3.rejected) {
                reject(rejected, "s3: " + problem);
            }
            s3.rejected.clear();
            if (System.in.available() < 0) {
                break;
            }
        }
    }

    private static synchronized void reject(Path file, String problem) {
        try {
            Files.writeString(file, problem + "\n", java.nio.file.StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static String read(Path directory, String name) throws IOException {
        return Files.readString(directory.resolve(name)).trim();
    }

    private static SSLContext tls(Path store) throws Exception {
        java.security.KeyStore keys = java.security.KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(store)) {
            keys.load(in, "store".toCharArray());
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance("PKIX");
        factory.init(keys, "store".toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(factory.getKeyManagers(), null, null);
        return context;
    }

    private static void respond(HttpExchange exchange, int status, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getRequestBody().readAllBytes();
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
