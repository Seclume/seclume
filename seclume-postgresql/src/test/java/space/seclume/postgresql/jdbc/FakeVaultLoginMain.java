package space.seclume.postgresql.jdbc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Vault for {@link VaultLoginHeapTest}, in a JVM of its own.
 *
 * <p>It makes up a JWT, an AWS secret key and session token, a client token
 * and a database password, writes each into a file in the directory it is
 * given - the test searches its own heap for them - and answers like Vault
 * over TLS 1.3: a JWT login only with exactly that JWT and the role
 * {@code app}; an AWS login only with a {@code GetCallerIdentity} request
 * whose SigV4 signature checks out against that key and that carries that
 * session token, as AWS would check it when Vault replays it; everything
 * else only with exactly the client token. A wrong byte anywhere is a 403,
 * so a test that gets through has sent what it should.
 *
 * <p>Prints {@code READY <port>}; when its standard input closes, prints what
 * it served and ends.
 */
public final class FakeVaultLoginMain {

    private static final String STORE_PASSWORD = "seclume-vault-test";

    private FakeVaultLoginMain() {
    }

    /** One request as it arrived; header names in lower case. */
    private record Request(String method, String path, Map<String, String> headers,
                           String body) {
        boolean is(String method, String path) {
            return this.method.equals(method) && this.path.equals(path);
        }
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        SecureRandom random = new SecureRandom();
        String jwt = base64url(random, 36) + "." + base64url(random, 120) + "."
                + base64url(random, 256);
        String clientToken = "hvs." + base64url(random, 72);
        String password = "A1a-" + base64url(random, 24);
        Files.writeString(directory.resolve("jwt.txt"), jwt + "\n");
        Files.writeString(directory.resolve("client-token.txt"), clientToken);
        Files.writeString(directory.resolve("password.txt"), password);
        String awsKey = base64url(random, 30).substring(0, 40);
        String awsSession = "IQoJb3JpZ2luX2Vj" + base64url(random, 600);
        Files.writeString(directory.resolve("aws-key.txt"), awsKey + "\n");
        Files.writeString(directory.resolve("aws-session.txt"), awsSession + "\n");

        AtomicInteger logins = new AtomicInteger();
        AtomicInteger renewals = new AtomicInteger();
        AtomicInteger fetches = new AtomicInteger();
        AtomicInteger leaseRevocations = new AtomicInteger();
        AtomicInteger tokenRevocations = new AtomicInteger();
        String tokenAnswer = "{\"auth\":{\"client_token\":\"" + clientToken
                + "\",\"lease_duration\":3600,\"renewable\":true}}";

        Path keystore = directory.resolve("vault.p12");
        SSLContext context = serverContext(keystore);
        Files.delete(keystore);
        try (SSLServerSocket socket = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(0, 8, InetAddress.getLoopbackAddress())) {
            Thread server = new Thread(() -> {
                while (!socket.isClosed()) {
                    try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                        accepted.setSoTimeout(30_000);
                        Request request = read(accepted.getInputStream());
                        int status;
                        String body;
                        if (request.is("POST", "/v1/auth/aws/login")) {
                            boolean right = AwsCheck.accepts(request.body(), awsKey, awsSession);
                            if (right) {
                                logins.incrementAndGet();
                            }
                            status = right ? 200 : 403;
                            body = right ? tokenAnswer : "{\"errors\":[\"denied\"]}";
                        } else if (request.is("POST", "/v1/auth/jwt/login")) {
                            boolean right = request.body().equals(
                                    "{\"role\":\"app\",\"jwt\":\"" + jwt + "\"}");
                            if (right) {
                                logins.incrementAndGet();
                            }
                            status = right ? 200 : 403;
                            body = right ? tokenAnswer : "{\"errors\":[\"denied\"]}";
                        } else if (!clientToken.equals(request.headers().get("x-vault-token"))) {
                            status = 403;
                            body = "{\"errors\":[\"permission denied\"]}";
                        } else if (request.is("GET", "/v1/database/creds/app")) {
                            fetches.incrementAndGet();
                            status = 200;
                            body = "{\"lease_id\":\"database/creds/app/1\",\"renewable\":true,"
                                    + "\"lease_duration\":3600,\"data\":{\"username\":"
                                    + "\"v-app-1\",\"password\":\"" + password + "\"}}";
                        } else if (request.is("POST", "/v1/auth/token/renew-self")) {
                            renewals.incrementAndGet();
                            status = 200;
                            body = tokenAnswer;
                        } else if (request.is("PUT", "/v1/sys/leases/revoke")) {
                            leaseRevocations.incrementAndGet();
                            status = 204;
                            body = "";
                        } else if (request.is("POST", "/v1/auth/token/revoke-self")) {
                            tokenRevocations.incrementAndGet();
                            status = 204;
                            body = "";
                        } else {
                            status = 404;
                            body = "{\"errors\":[]}";
                        }
                        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                        OutputStream out = accepted.getOutputStream();
                        out.write(("HTTP/1.1 " + status + " \r\n"
                                + (bytes.length == 0 ? "" : "Content-Type: application/json\r\n")
                                + "Content-Length: " + bytes.length + "\r\n"
                                + "Connection: close\r\n\r\n")
                                .getBytes(StandardCharsets.US_ASCII));
                        out.write(bytes);
                        out.flush();
                    } catch (IOException closedOrFailed) {
                        // the next connection, or the end
                    }
                }
            }, "fake-vault");
            server.setDaemon(true);
            server.start();

            System.out.println("READY " + socket.getLocalPort());
            System.out.flush();
            while (System.in.read() >= 0) {
                // until the test closes the pipe
            }
            System.out.println("DONE logins=" + logins + " renewals=" + renewals
                    + " fetches=" + fetches + " lease-revocations=" + leaseRevocations
                    + " token-revocations=" + tokenRevocations);
        }
    }

    /** What AWS does with the request Vault replays: recompute SigV4 and compare. */
    private static final class AwsCheck {

        static boolean accepts(String body, String secretKey, String sessionToken) {
            try {
                Map<String, String> login = fields(body);
                if (!"app".equals(login.get("role"))
                        || !"POST".equals(login.get("iam_http_request_method"))
                        || !"https://sts.amazonaws.com/".equals(b64(login.get("iam_request_url")))) {
                    return false;
                }
                String stsBody = b64(login.get("iam_request_body"));
                Map<String, String> headers = fields(b64(login.get("iam_request_headers")));
                if (!sessionToken.equals(headers.get("X-Amz-Security-Token"))) {
                    return false;
                }
                java.util.TreeMap<String, String> canonical = new java.util.TreeMap<>();
                headers.forEach((name, value) -> {
                    if (!name.equalsIgnoreCase("Authorization")) {
                        canonical.put(name.toLowerCase(Locale.ROOT), value.trim());
                    }
                });
                StringBuilder request = new StringBuilder("POST\n/\n\n");
                canonical.forEach((name, value) -> request.append(name).append(':')
                        .append(value).append('\n'));
                String signed = String.join(";", canonical.keySet());
                request.append('\n').append(signed).append('\n').append(sha256(stsBody));
                String date = headers.get("X-Amz-Date");
                String day = date.substring(0, 8);
                String scope = day + "/us-east-1/sts/aws4_request";
                String toSign = "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n"
                        + sha256(request.toString());
                byte[] key = hmac(("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8), day);
                key = hmac(hmac(hmac(key, "us-east-1"), "sts"), "aws4_request");
                String expected = "AWS4-HMAC-SHA256 Credential=AKIASECLUMEHEAPTEST1/" + scope
                        + ", SignedHeaders=" + signed + ", Signature="
                        + java.util.HexFormat.of().formatHex(hmac(key, toSign));
                return expected.equals(headers.get("Authorization"));
            } catch (Exception malformed) {
                return false;
            }
        }

        private static Map<String, String> fields(String json) {
            Map<String, String> fields = new LinkedHashMap<>();
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\"([^\"]+)\":\"((?:[^\"\\\\]++|\\\\.)*+)\"").matcher(json);
            while (m.find()) {
                fields.put(m.group(1), m.group(2).replace("\\\"", "\"")
                        .replace("\\\\", "\\"));
            }
            return fields;
        }

        private static String b64(String text) {
            return new String(Base64.getDecoder().decode(text), StandardCharsets.UTF_8);
        }

        private static byte[] hmac(byte[] key, String data) throws Exception {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        }

        private static String sha256(String text) throws Exception {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest
                    .getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        }
    }

    private static Request read(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) >= 0) {
            head.write(b);
            byte[] seen = head.toByteArray();
            int n = seen.length;
            if (n >= 4 && seen[n - 4] == '\r' && seen[n - 3] == '\n' && seen[n - 2] == '\r'
                    && seen[n - 1] == '\n') {
                break;
            }
        }
        String[] lines = head.toString(StandardCharsets.US_ASCII).split("\r\n");
        String[] requestLine = lines[0].split(" ");
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.put(lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT),
                        lines[i].substring(colon + 1).trim());
            }
        }
        int length;
        try {
            length = Integer.parseInt(headers.getOrDefault("content-length", "0").trim());
        } catch (NumberFormatException e) {
            throw new IOException("a Content-Length that is no number", e);
        }
        if (length < 0) {
            throw new IOException("a negative Content-Length");
        }
        return new Request(requestLine[0], requestLine[1], headers,
                new String(in.readNBytes(length), StandardCharsets.UTF_8));
    }

    /** A self-signed certificate for 127.0.0.1 from the JDK's keytool, in a TLS 1.3 context. */
    private static SSLContext serverContext(Path keystore) throws Exception {
        String keytool = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool")
                .toString();
        Process process = new ProcessBuilder(List.of(keytool, "-genkeypair", "-alias", "vault",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                "-dname", "CN=localhost", "-ext", "san=dns:localhost,ip:127.0.0.1",
                "-storetype", "PKCS12", "-keystore", keystore.toString(),
                "-storepass", STORE_PASSWORD, "-keypass", STORE_PASSWORD))
                .redirectErrorStream(true).start();
        process.getInputStream().readAllBytes();
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed");
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, STORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, STORE_PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), null, null);
        return context;
    }

    private static String base64url(SecureRandom random, int bytes) {
        byte[] raw = new byte[bytes];
        random.nextBytes(raw);
        return new String(Base64.getUrlEncoder().withoutPadding().encode(raw),
                StandardCharsets.US_ASCII);
    }
}
