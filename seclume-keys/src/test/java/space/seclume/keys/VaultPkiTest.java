package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.PrivateSigningKey;

/**
 * Certificates from a stand-in for Vault's PKI engine that signs the way Vault
 * does - checks the request's signature, signs for the key in it - with the
 * {@code openssl} command line and a throwaway CA. The key is generated in
 * OpenSSL and the certificate then carries a TLS handshake that asks for it.
 */
@Timeout(120)
class VaultPkiTest {

    private static Path directory;
    private static Path token;
    private static SSLContext serverTls;
    private static TrustManagerFactory trustingTheCa;

    @BeforeAll
    static void ca() throws Exception {
        Assumptions.assumeTrue(PrivateSigningKey.available(), "no OpenSSL 3 here");
        directory = Files.createTempDirectory("seclume-vault-pki");
        openssl(directory, "req", "-x509", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-subj",
                "/CN=seclume test PKI", "-keyout", "ca.key", "-out", "ca.pem");
        openssl(directory, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-subj", "/CN=vault", "-keyout", "vault.key", "-out", "vault.csr");
        Files.writeString(directory.resolve("vault.ext"),
                "subjectAltName=IP:127.0.0.1,DNS:localhost\n");
        openssl(directory, "x509", "-req", "-in", "vault.csr", "-CA", "ca.pem", "-CAkey",
                "ca.key", "-CAcreateserial", "-days", "2", "-extfile", "vault.ext", "-out",
                "vault.pem");
        token = Files.writeString(directory.resolve("token"), "hvs.test-token-" + System.nanoTime());
        serverTls = SeclumeKeys.sslContext(directory.resolve("vault.pem"),
                "provider=file&path=" + directory.resolve("vault.key"));
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setCertificateEntry("ca", SeclumeKeys.certificates(directory.resolve("ca.pem"))[0]);
        trustingTheCa = TrustManagerFactory.getInstance("PKIX");
        trustingTheCa.init(store);
    }

    @AfterAll
    static void clean() throws IOException {
        if (directory != null) {
            try (var files = Files.walk(directory)) {
                for (Path file : files.sorted(Collections.reverseOrder()).toList()) {
                    Files.deleteIfExists(file);
                }
            }
        }
    }

    private static String openssl(Path in, String... arguments) throws IOException {
        List<String> command = new ArrayList<>();
        command.add("openssl");
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).directory(in.toFile())
                .redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        try {
            if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new IOException("openssl " + arguments[0] + " failed: " + output);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
        return output;
    }

    /** What Vault's {@code pki/sign} does with a request, by the command line. */
    static String sign(String csr, String ttlDays, String altNames) throws IOException {
        Path work = Files.createTempDirectory(directory, "sign");
        Files.writeString(work.resolve("req.pem"), csr);
        openssl(work, "req", "-in", "req.pem", "-verify", "-noout");   // refuses a bad signature
        StringBuilder ext = new StringBuilder("extendedKeyUsage=clientAuth\n");
        if (altNames != null) {
            ext.append("subjectAltName=");
            String[] names = altNames.split(",");
            for (int i = 0; i < names.length; i++) {
                ext.append(i == 0 ? "" : ",").append("DNS:").append(names[i].trim());
            }
            ext.append('\n');
        }
        Files.writeString(work.resolve("ext"), ext.toString());
        openssl(work, "x509", "-req", "-in", "req.pem", "-CA", "../ca.pem", "-CAkey",
                "../ca.key", "-CAcreateserial", "-days", ttlDays, "-extfile", "ext",
                "-out", "cert.pem");
        return Files.readString(work.resolve("cert.pem"));
    }

    static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        return m.find() ? m.group(1).replace("\\n", "\n").replace("\\/", "/") : null;
    }

    static String jsonText(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    /** Vault's answer to a signed request. */
    static String signed(String certificate) throws IOException {
        String ca = Files.readString(directory.resolve("ca.pem"));
        return "{\"request_id\":\"1\",\"data\":{\"certificate\":\"" + jsonText(certificate)
                + "\",\"issuing_ca\":\"" + jsonText(ca) + "\",\"ca_chain\":[\"" + jsonText(ca)
                + "\"],\"serial_number\":\"01\"}}";
    }

    private String spec(FakeVault vault, String more) {
        return "address=" + vault.address() + "&verify=false&pki-role=client"
                + "&common-name=orders.seclume.test&alt-names=orders.svc&ttl=1h"
                + "&token-provider=file&token-path=" + token + more;
    }

    @Test
    void aCertificateForAKeyThatNeverLeftOpenSsl() throws Exception {
        try (FakeVault vault = new FakeVault(request -> new Answer(200,
                signed(sign(field(request.body(), "csr"), "1",
                        field(request.body(), "alt_names")))))) {
            X509ExtendedKeyManager manager = SeclumeKeys.vaultPkiKeyManager(spec(vault, ""));
            try {
                Request request = vault.requests().get(0);
                assertEquals("POST /v1/pki/sign/client", request.method() + " " + request.path());
                assertEquals(Files.readString(token), request.header("X-Vault-Token"));
                assertEquals("orders.seclume.test", field(request.body(), "common_name"));
                assertEquals("1h", field(request.body(), "ttl"));
                assertFalse(request.body().contains("PRIVATE"), "a private key in the request");

                X509Certificate[] chain = manager.getCertificateChain("seclume");
                assertEquals(2, chain.length, "the certificate and its issuer");
                assertTrue(chain[0].getSubjectX500Principal().getName()
                        .contains("CN=orders.seclume.test"));
                assertEquals(chain[1].getSubjectX500Principal(), chain[0].getIssuerX500Principal());
                assertTrue(manager.getPrivateKey("seclume") instanceof OpenSslPrivateKey,
                        "the key is not OpenSSL's");
                assertEquals("CN=orders.seclume.test", handshake(manager));
            } finally {
                ((AutoCloseable) manager).close();
            }
        }
    }

    @Test
    void aRenewalBringsANewKeyAndAHandshakeUnderwayKeepsTheOld() throws Exception {
        try (FakeVault vault = new FakeVault(request -> new Answer(200,
                signed(sign(field(request.body(), "csr"), "1", null))))) {
            try (VaultPkiKeyManager manager = (VaultPkiKeyManager)
                    SeclumeKeys.vaultPkiKeyManager(spec(vault, ""))) {
                String first = manager.chooseClientAlias(new String[] {"EC"}, null, null);
                X509Certificate before = manager.getCertificateChain(first)[0];
                Instant end = before.getNotAfter().toInstant();
                Instant start = before.getNotBefore().toInstant();
                assertEquals(VaultPkiKeyManager.renewalTime(start, end, 0.67),
                        manager.nextRenewal());
                assertEquals(end, manager.notAfter());

                manager.renewNow();
                assertEquals(2, manager.generations());
                String second = manager.chooseClientAlias(new String[] {"EC"}, null, null);
                assertNotEquals(first, second);
                X509Certificate after = manager.getCertificateChain(second)[0];
                assertNotEquals(before.getSerialNumber(), after.getSerialNumber());
                assertNotEquals(before.getPublicKey(), after.getPublicKey(), "the same key again");
                assertEquals(before, manager.getCertificateChain(first)[0],
                        "a handshake that chose the old alias lost its certificate");
                assertNotEquals(manager.getPrivateKey(first), manager.getPrivateKey(second));
                assertEquals("CN=orders.seclume.test", handshake(manager));
            }
        }
    }

    /**
     * What an endpoint and a recording see: the certificate listed under its
     * name with its validity and next renewal, a failed renewal with its
     * reason - and gone from the list once closed.
     */
    @Test
    void aRenewalThatFailsIsListedAndRecorded(@org.junit.jupiter.api.io.TempDir Path recordings)
            throws Exception {
        java.util.concurrent.atomic.AtomicBoolean refuse =
                new java.util.concurrent.atomic.AtomicBoolean();
        Path recording = recordings.resolve("events.jfr");
        try (FakeVault vault = new FakeVault(request -> refuse.get()
                ? new Answer(503, "{\"errors\":[\"sealed\"]}")
                : new Answer(200, signed(sign(field(request.body(), "csr"), "1", null))));
             jdk.jfr.Recording jfr = new jdk.jfr.Recording()) {
            jfr.enable("space.seclume.CertificateRenewal");
            jfr.start();
            VaultPkiKeyManager manager = (VaultPkiKeyManager)
                    SeclumeKeys.vaultPkiKeyManager(spec(vault, "&name=orders-client"));
            try {
                ManagedCertificate listed = SeclumeKeys.managedCertificates().stream()
                        .filter(c -> c.name().equals("orders-client")).findFirst().orElseThrow();
                assertEquals("vault-pki", listed.kind());
                assertTrue(listed.subject().contains("CN=orders.seclume.test"));
                assertEquals(manager.notAfter(), listed.notAfter());
                assertEquals(manager.nextRenewal(), listed.nextRenewal());
                assertEquals(null, listed.lastFailure());

                refuse.set(true);
                assertThrows(IOException.class, manager::renewNow);
                ManagedCertificate failing = SeclumeKeys.managedCertificates().stream()
                        .filter(c -> c.name().equals("orders-client")).findFirst().orElseThrow();
                assertTrue(failing.lastFailure().contains("503"), failing.lastFailure());
                assertEquals(listed.notAfter(), failing.notAfter(), "the one in hand stays");

                refuse.set(false);
                manager.renewNow();
                assertEquals(null, SeclumeKeys.managedCertificates().stream()
                        .filter(c -> c.name().equals("orders-client")).findFirst()
                        .orElseThrow().lastFailure(), "a success clears the failure");
            } finally {
                manager.close();
            }
            assertTrue(SeclumeKeys.managedCertificates().stream()
                    .noneMatch(c -> c.name().equals("orders-client")), "listed after close");
            jfr.stop();
            jfr.dump(recording);
        }
        List<jdk.jfr.consumer.RecordedEvent> events = jdk.jfr.consumer.RecordingFile
                .readAllEvents(recording).stream()
                .filter(e -> e.getEventType().getName().equals("space.seclume.CertificateRenewal"))
                .toList();
        assertEquals(List.of(true, false, true),
                events.stream().map(e -> e.getBoolean("succeeded")).toList());
        assertEquals("orders-client", events.get(0).getString("certificate"));
        assertEquals("/v1/pki/sign/client", events.get(0).getString("source"));
        assertTrue(events.get(1).getString("reason").contains("503"));
        assertTrue(events.get(0).getLong("notAfter") > System.currentTimeMillis());
        assertFalse(events.toString().contains(Files.readString(token)), "the token is recorded");
    }

    @Test
    void aCertificateForAnotherKeyIsRefused() throws Exception {
        // A request made by the command line, signed - the certificate is for its key.
        openssl(directory, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-subj", "/CN=someone-else", "-keyout", "other.key", "-out",
                "other.csr");
        String foreign = signed(sign(Files.readString(directory.resolve("other.csr")), "1",
                null));
        try (FakeVault vault = new FakeVault(request -> new Answer(200, foreign))) {
            IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> SeclumeKeys.vaultPkiKeyManager(spec(vault, "")));
            assertTrue(refused.getMessage().contains("another key"), refused.getMessage());
        }
    }

    @Test
    void aRefusalSaysWhatWasRefusedAndNeverTheToken() throws Exception {
        try (FakeVault vault = new FakeVault(request -> new Answer(403,
                "{\"errors\":[\"permission denied\"]}"))) {
            IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> SeclumeKeys.vaultPkiKeyManager(spec(vault, "&pki-mount=pki_int")));
            assertTrue(refused.getMessage().contains("403")
                    && refused.getMessage().contains("/v1/pki_int/sign/client"),
                    refused.getMessage());
            assertFalse(refused.getMessage().contains(Files.readString(token)));
        }
    }

    @Test
    void settingsThatCannotWorkAreRefusedBeforeAnythingIsSent() {
        String base = "address=https://127.0.0.1:1&pki-role=client&common-name=a"
                + "&token-provider=file&token-path=" + token;
        for (String[] bad : new String[][] {
            {base.replace("https://", "http://"), "https://"},
            {base.replace("&pki-role=client", ""), "pki-role"},
            {base.replace("&common-name=a", ""), "common-name"},
            {base + "&renew-at=0.99", "renew-at"},
            {base + "&pki-mount=pki%20int", "path names"},
        }) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> SeclumeKeys.vaultPkiKeyManager(bad[0]), bad[0]);
            assertTrue(refused.getMessage().contains(bad[1]), refused.getMessage());
        }
    }

    @Test
    void whenToRenewAndWhenToTryAgain() {
        Instant start = Instant.parse("2026-01-01T00:00:00Z");
        assertEquals(start.plus(Duration.ofHours(16)),
                VaultPkiKeyManager.renewalTime(start, start.plus(Duration.ofHours(24)), 2.0 / 3));
        // a tenth of what is left, between ten seconds and five minutes
        assertEquals(Duration.ofMinutes(5),
                VaultPkiKeyManager.retryAfter(start, start.plus(Duration.ofHours(8))));
        assertEquals(Duration.ofSeconds(60),
                VaultPkiKeyManager.retryAfter(start, start.plus(Duration.ofMinutes(10))));
        assertEquals(Duration.ofSeconds(10),
                VaultPkiKeyManager.retryAfter(start, start.minus(Duration.ofMinutes(1))));
    }

    @Test
    void theRequestBodyIsJson() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("csr", "-----BEGIN-----\nAB\"C\\\n");
        fields.put("x", "\u0001");
        assertEquals("{\"csr\":\"-----BEGIN-----\\nAB\\\"C\\\\\\n\",\"x\":\"\\u0001\"}",
                VaultPkiKeyManager.json(fields));
    }

    /** A TLS 1.3 handshake with a server that asks for a client certificate; what it saw. */
    private static String handshake(X509ExtendedKeyManager manager) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverContext().getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setNeedClientAuth(true);
            CompletableFuture<String> peer = CompletableFuture.supplyAsync(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    accepted.startHandshake();
                    String name = accepted.getSession().getPeerPrincipal().getName();
                    accepted.getOutputStream().write(1);
                    accepted.getOutputStream().flush();
                    return name;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            SSLContext client = SSLContext.getInstance("TLSv1.3");
            client.init(new KeyManager[] {manager}, trustingTheCa.getTrustManagers(), null);
            try (SSLSocket socket = (SSLSocket) client.getSocketFactory()
                    .createSocket(InetAddress.getLoopbackAddress(), listener.getLocalPort())) {
                socket.startHandshake();
                assertEquals(1, socket.getInputStream().read());
            }
            return peer.get(30, TimeUnit.SECONDS);
        }
    }

    private static SSLContext serverContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(SeclumeKeys.keyManagerFactory(directory.resolve("vault.pem"),
                "provider=file&path=" + directory.resolve("vault.key")).getKeyManagers(),
                trustingTheCa.getTrustManagers(), null);
        return context;
    }

    record Request(String method, String path, Map<String, String> headers, String body) {
        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }

    record Answer(int status, String body) {
    }

    interface Handler {
        Answer answer(Request request) throws IOException;
    }

    /** Vault over HTTPS, one request per connection, every request kept. */
    static final class FakeVault implements AutoCloseable {

        private final SSLServerSocket socket;
        private final List<Request> requests = new java.util.concurrent.CopyOnWriteArrayList<>();
        private volatile boolean stopped;

        FakeVault(Handler handler) throws IOException {
            socket = (SSLServerSocket) serverTls.getServerSocketFactory()
                    .createServerSocket(0, 8, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(() -> serve(handler), "fake-vault-pki");
            thread.setDaemon(true);
            thread.start();
        }

        String address() {
            return "https://127.0.0.1:" + socket.getLocalPort();
        }

        List<Request> requests() {
            return requests;
        }

        private void serve(Handler handler) {
            while (!stopped) {
                try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                    Request request = read(accepted.getInputStream());
                    requests.add(request);
                    Answer answer;
                    try {
                        answer = handler.answer(request);
                    } catch (IOException e) {
                        answer = new Answer(400, "{\"errors\":[\"" + jsonText(e.getMessage())
                                + "\"]}");
                    }
                    byte[] body = answer.body().getBytes(StandardCharsets.UTF_8);
                    OutputStream out = accepted.getOutputStream();
                    out.write(("HTTP/1.1 " + answer.status() + " \r\nContent-Type: "
                            + "application/json\r\nContent-Length: " + body.length
                            + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.write(body);
                    out.flush();
                } catch (IOException e) {
                    if (stopped) {
                        return;
                    }
                }
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

        @Override
        public void close() throws IOException {
            stopped = true;
            socket.close();
        }
    }
}
