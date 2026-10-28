package space.seclume.secret;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import space.seclume.tls.TestCertificates;

/**
 * An HTTPS server that answers like Vault, routed by method and path, and
 * that keeps every request whole - headers <b>and</b> body - so a test can
 * look at what a login sent.
 *
 * <p>A real {@code SSLServerSocket}, as in {@code VaultSecretProviderTest}:
 * the TLS, the hand-written HTTP/1.1 and the JSON reader are all on the route.
 * What it cannot show is Vault's own behaviour; the answers are the shapes
 * Vault's API documentation gives.
 */
final class FakeVaultServer implements AutoCloseable {

    /** One request as it arrived. Header names in lower case. */
    record Request(String method, String path, Map<String, String> headers, String body) {

        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }

        boolean is(String method, String path) {
            return this.method.equals(method) && this.path.equals(path);
        }
    }

    /** A status and a body; 204 is sent without one. */
    record Answer(int status, String body) {
    }

    /** Decides the answer to each request. */
    interface Handler {
        Answer answer(Request request);
    }

    /**
     * Fixed answers per {@code METHOD /path}, taken in turn; the last one
     * repeats. A request nobody scripted is answered 404, as Vault answers a
     * path nothing is mounted at.
     */
    static final class Script implements Handler {

        private final Map<String, Deque<Answer>> answers = new HashMap<>();

        Script on(String method, String path, int status, String... bodies) {
            Deque<Answer> queue = answers.computeIfAbsent(method + " " + path,
                    key -> new ArrayDeque<>());
            for (String body : bodies) {
                queue.add(new Answer(status, body));
            }
            return this;
        }

        @Override
        public synchronized Answer answer(Request request) {
            Deque<Answer> queue = answers.get(request.method() + " " + request.path());
            if (queue == null || queue.isEmpty()) {
                return new Answer(404, "{\"errors\":[]}");
            }
            return queue.size() > 1 ? queue.removeFirst() : queue.peekFirst();
        }
    }

    private final SSLServerSocket socket;
    private final Thread thread;
    private final Handler handler;
    private final List<Request> requests = new CopyOnWriteArrayList<>();
    private volatile boolean stopped;

    FakeVaultServer(SSLContext context, Handler handler) throws IOException {
        this.handler = handler;
        this.socket = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(0, 8, InetAddress.getLoopbackAddress());
        this.thread = new Thread(this::serve, "fake-vault-server");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    /** A TLS 1.3 server context with a certificate for 127.0.0.1 from a throwaway CA. */
    static SSLContext context(TestCertificates certificates) throws Exception {
        TestCertificates.Issued vault = certificates.issue("vault",
                "san=dns:vault.example.com,ip:127.0.0.1", "eku=serverAuth");
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(vault.keystore())) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        KeyManagerFactory keys =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestCertificates.PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), null, null);
        return context;
    }

    int port() {
        return socket.getLocalPort();
    }

    String address() {
        return "https://127.0.0.1:" + port();
    }

    List<Request> requests() {
        return requests;
    }

    /** The requests to one path, in order. */
    List<Request> requests(String method, String path) {
        return requests.stream().filter(r -> r.is(method, path)).toList();
    }

    private void serve() {
        while (!stopped) {
            try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                accepted.setSoTimeout(30_000);
                Request request = read(accepted.getInputStream());
                requests.add(request);
                Answer answer = handler.answer(request);
                byte[] body = answer.status() == 204 ? new byte[0]
                        : answer.body().getBytes(StandardCharsets.UTF_8);
                OutputStream out = accepted.getOutputStream();
                out.write(("HTTP/1.1 " + answer.status() + " \r\n"
                        + (body.length == 0 ? "" : "Content-Type: application/json\r\n")
                        + "Content-Length: " + body.length + "\r\n"
                        + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.write(body);
                out.flush();
            } catch (Exception stoppedOrFailed) {
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
        byte[] body = in.readNBytes(contentLength(headers));
        return new Request(requestLine[0], requestLine[1], headers,
                new String(body, StandardCharsets.UTF_8));
    }

    /** The declared body length; a header that is no number is a request this server will not read. */
    private static int contentLength(Map<String, String> headers) throws IOException {
        try {
            int length = Integer.parseInt(headers.getOrDefault("content-length", "0").trim());
            if (length < 0) {
                throw new IOException("a negative Content-Length");
            }
            return length;
        } catch (NumberFormatException e) {
            throw new IOException("a Content-Length that is no number", e);
        }
    }

    @Override
    public void close() throws IOException {
        stopped = true;
        socket.close();
    }
}
