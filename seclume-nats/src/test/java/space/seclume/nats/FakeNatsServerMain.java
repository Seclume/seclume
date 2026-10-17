package space.seclume.nats;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import io.nats.client.NKey;
import space.seclume.internal.TrustChoice;

/**
 * A NATS 2.x TLS server in a JVM of its own, for the heap proof and protocol
 * tests.
 *
 * <p>Generates:
 * <ul>
 *   <li>a user NKey seed ({@code user.nk}, and its raw 32-byte Ed25519 seed in
 *       {@code user-seed.bin});
 *   <li>a {@code user.creds} file containing a user JWT and a second NKey seed
 *       ({@code creds-seed.txt} and its raw 32-byte seed {@code creds-seed.bin});
 *   <li>a password ({@code password.txt}) for user {@code orders};
 *   <li>a token ({@code token.txt}).
 * </ul>
 *
 * <p>On each connection, sends {@code INFO {"server_id":"S1","version":"2.10.24",
 * "proto":1,"tls_required":true,"nonce":"<random>","headers":true,"max_payload":1048576}\r\n},
 * upgrades the socket to TLS 1.3, reads {@code CONNECT {...}\r\n}, verifies
 * the NKey signature, {@code .creds} JWT + signature, password, or token, and
 * answers {@code PING\r\n} with {@code PONG\r\n} as well as echoing published
 * messages to matching {@code SUB} subscriptions.
 */
public final class FakeNatsServerMain {

    private static final String STORE_PASSWORD = "seclume-nats-test";
    static final String USER_JWT = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyIn0.c2ln";

    private FakeNatsServerMain() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        SecureRandom random = new SecureRandom();

        // 1. NKey seed
        byte[] rawNkeySeed = new byte[32];
        random.nextBytes(rawNkeySeed);
        NKey nkey = createUserFromRawSeed(rawNkeySeed);
        String nkeySeedText = new String(nkey.getSeed());
        String nkeyPublicText = new String(nkey.getPublicKey());
        Files.writeString(directory.resolve("user.nk"), nkeySeedText, StandardCharsets.US_ASCII);
        Files.write(directory.resolve("user-seed.bin"), rawNkeySeed);

        // 2. .creds file (JWT + second NKey seed)
        byte[] rawCredsSeed = new byte[32];
        random.nextBytes(rawCredsSeed);
        NKey credsKey = createUserFromRawSeed(rawCredsSeed);
        String credsSeedText = new String(credsKey.getSeed());
        String credsPublicText = new String(credsKey.getPublicKey());
        String credsFileContent = """
                -----BEGIN NATS USER JWT-----
                %s
                ------END NATS USER JWT------

                -----BEGIN USER NKEY SEED-----
                %s
                ------END USER NKEY SEED-----
                """.formatted(USER_JWT, credsSeedText);
        Files.writeString(directory.resolve("user.creds"), credsFileContent, StandardCharsets.US_ASCII);
        Files.writeString(directory.resolve("creds-seed.txt"), credsSeedText, StandardCharsets.US_ASCII);
        Files.write(directory.resolve("creds-seed.bin"), rawCredsSeed);

        // 3. Password & Token
        String password = "nats-pw-" + HexFormat.of().formatHex(random.generateSeed(16));
        String token = "nats-tok-" + HexFormat.of().formatHex(random.generateSeed(16));
        Files.writeString(directory.resolve("password.txt"), password, StandardCharsets.US_ASCII);
        Files.writeString(directory.resolve("token.txt"), token, StandardCharsets.US_ASCII);

        // 4. TLS PKCS12 keystore
        Path keystore = directory.resolve("server.p12");
        String pin = generateKeystore(keystore);
        SSLContext sslContext = serverSslContext(keystore);
        SSLSocketFactory sslFactory = sslContext.getSocketFactory();

        AtomicInteger authenticatedConnections = new AtomicInteger();

        Thread acceptLoop;
        try (ServerSocket listener = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            acceptLoop = Thread.ofVirtual().start(() -> {
                while (!listener.isClosed()) {
                    try {
                        Socket plain = listener.accept();
                        Thread.ofVirtual().start(() -> handleClient(plain, sslFactory,
                                nkey, nkeyPublicText, credsKey, credsPublicText,
                                password, token, authenticatedConnections));
                    } catch (IOException ignored) {
                        break;
                    }
                }
            });

            System.out.println("READY " + listener.getLocalPort() + " " + pin);
            System.out.flush();
            while (System.in.read() >= 0) {
                // serve until the test closes stdin
            }
        }
        acceptLoop.join(2000);
        System.out.println("AUTHENTICATED " + authenticatedConnections.get());
        System.out.flush();
    }

    private static NKey createUserFromRawSeed(byte[] raw32) throws Exception {
        return NKey.fromSeed(encodeSeedWithOfficial(raw32));
    }

    private static char[] encodeSeedWithOfficial(byte[] raw32) throws Exception {
        var method = NKey.class.getDeclaredMethod("encodeSeed", NKey.Type.class, byte[].class);
        method.setAccessible(true);
        return (char[]) method.invoke(null, NKey.Type.USER, raw32);
    }

    private static void handleClient(Socket plain, SSLSocketFactory sslFactory,
                                     NKey nkey, String nkeyPub,
                                     NKey credsKey, String credsPub,
                                     String expectedPassword, String expectedToken,
                                     AtomicInteger authenticatedConnections) {
        try (Socket socket = plain) {
            socket.setSoTimeout(15_000);
            String nonce = "nonce-" + System.nanoTime();
            String info = "INFO {\"server_id\":\"SECLUME_TEST\",\"version\":\"2.10.24\","
                    + "\"proto\":1,\"host\":\"127.0.0.1\",\"port\":" + socket.getLocalPort()
                    + ",\"max_payload\":1048576,\"headers\":true,\"tls_required\":true,"
                    + "\"nonce\":\"" + nonce + "\"}\r\n";
            OutputStream rawOut = socket.getOutputStream();
            rawOut.write(info.getBytes(StandardCharsets.US_ASCII));
            rawOut.flush();

            try (SSLSocket tls = (SSLSocket) sslFactory.createSocket(
                    socket, "localhost", socket.getPort(), true)) {
                tls.setUseClientMode(false);
                tls.setEnabledProtocols(new String[] {"TLSv1.3"});
                tls.startHandshake();

                BufferedReader in = new BufferedReader(
                        new InputStreamReader(tls.getInputStream(), StandardCharsets.UTF_8));
                OutputStream out = tls.getOutputStream();

                String connectLine = in.readLine();
                if (connectLine == null || !connectLine.startsWith("CONNECT ")) {
                    return;
                }
                String json = connectLine.substring("CONNECT ".length()).trim();
                String error = verifyAuth(json, nonce, nkey, nkeyPub, credsKey, credsPub,
                        expectedPassword, expectedToken);
                if (error != null) {
                    out.write(("-ERR '" + error + "'\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    return;
                }
                authenticatedConnections.incrementAndGet();

                String activeSub = null;
                String activeSid = "1";
                String line;
                while ((line = in.readLine()) != null) {
                    if (line.equals("PING")) {
                        out.write("PONG\r\n".getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                    } else if (line.startsWith("SUB ")) {
                        String[] parts = line.split(" ");
                        if (parts.length >= 3) {
                            activeSub = parts[1];
                            activeSid = parts[parts.length - 1];
                        }
                    } else if (line.startsWith("PUB ")) {
                        String[] parts = line.split(" ");
                        String subject = parts[1];
                        int bytes = Integer.parseInt(parts[parts.length - 1]);
                        char[] payload = new char[bytes];
                        int read = 0;
                        while (read < bytes) {
                            int n = in.read(payload, read, bytes - read);
                            if (n < 0) {
                                return;
                            }
                            read += n;
                        }
                        in.readLine(); // trailing CRLF of PUB payload
                        if (activeSub != null && subject.equals(activeSub)) {
                            String msg = "MSG " + subject + " " + activeSid + " " + bytes + "\r\n"
                                    + new String(payload) + "\r\n";
                            out.write(msg.getBytes(StandardCharsets.UTF_8));
                            out.flush();
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // client closed or handshake failed
        }
    }

    private static String verifyAuth(String json, String nonce,
                                     NKey nkey, String nkeyPub,
                                     NKey credsKey, String credsPub,
                                     String expectedPassword, String expectedToken) {
        try {
            String nkeyField = jsonField(json, "nkey");
            if (nkeyField != null && !nkeyField.isEmpty()) {
                String sigField = jsonField(json, "sig");
                String jwtField = jsonField(json, "jwt");
                if (sigField == null) {
                    return "Authorization Violation";
                }
                byte[] sig = Base64.getUrlDecoder().decode(sigField);
                byte[] nonceBytes = nonce.getBytes(StandardCharsets.US_ASCII);
                if (nkeyField.equals(nkeyPub) && (jwtField == null || jwtField.isEmpty())) {
                    return nkey.verify(nonceBytes, sig) ? null : "Authorization Violation";
                }
                if (nkeyField.equals(credsPub) && USER_JWT.equals(jwtField)) {
                    return credsKey.verify(nonceBytes, sig) ? null : "Authorization Violation";
                }
                return "Authorization Violation";
            }
            String user = jsonField(json, "user");
            if (user != null) {
                String pass = jsonField(json, "pass");
                if ("orders".equals(user) && expectedPassword.equals(pass)) {
                    return null;
                }
                return "Authorization Violation";
            }
            String token = jsonField(json, "auth_token");
            if (token != null) {
                if (expectedToken.equals(token)) {
                    return null;
                }
                return "Authorization Violation";
            }
            return "Authorization Violation";
        } catch (Exception e) {
            return "Authorization Violation";
        }
    }

    private static String jsonField(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int idx = json.indexOf(pattern);
        if (idx < 0) {
            return null;
        }
        int start = idx + pattern.length();
        StringBuilder out = new StringBuilder();
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(++i);
                switch (next) {
                    case '"', '\\', '/' -> out.append(next);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    default -> out.append(next);
                }
            } else if (c == '"') {
                return out.toString();
            } else {
                out.append(c);
            }
        }
        return null;
    }

    private static String generateKeystore(Path keystore) throws Exception {
        String keytool = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool")
                .toString();
        Process process = new ProcessBuilder(List.of(keytool, "-genkeypair", "-alias", "server",
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
        return TrustChoice.pinOf((X509Certificate) store.getCertificate("server"));
    }

    private static SSLContext serverSslContext(Path keystore) throws Exception {
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
}
