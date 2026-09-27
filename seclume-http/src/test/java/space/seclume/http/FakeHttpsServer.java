package space.seclume.http;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

/**
 * A small HTTPS server for the tests (the JDK's TLS 1.3): it checks the
 * credential header against what it was given, records every request, and
 * answers by path - a fixed length, chunked, up to the close, 204, a redirect
 * - so the client's reading of each can be checked.
 *
 * <p>Strict where it matters: a request without the right credential gets a
 * 401, and one with it twice, or with a malformed head, a 400.
 */
final class FakeHttpsServer implements AutoCloseable {

    /** One request as the server took it. */
    record Received(String method, String target, Map<String, List<String>> headers,
                    String body, boolean authorized) {
    }

    // what it expects
    String headerName = "Authorization";
    byte[] expected = "Bearer ya29.test-token".getBytes(StandardCharsets.UTF_8);
    /** Close each connection after its first answer, without saying so. */
    volatile boolean dropSilently;

    // what it saw
    final List<Received> received = new CopyOnWriteArrayList<>();
    final AtomicInteger connections = new AtomicInteger();

    private final SSLServerSocket listener;

    FakeHttpsServer(SSLContext tls) throws IOException {
        listener = (SSLServerSocket) tls.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        listener.setEnabledProtocols(new String[] {"TLSv1.3"});
    }

    /** The port - and the start of serving it, once every field is set. */
    synchronized int port() {
        if (acceptor == null) {
            acceptor = new Thread(this::accept, "fake-https");
            acceptor.setDaemon(true);
            acceptor.start();
        }
        return listener.getLocalPort();
    }

    private Thread acceptor;

    private void accept() {
        while (!listener.isClosed()) {
            try {
                Socket socket = listener.accept();
                connections.incrementAndGet();
                Thread session = new Thread(() -> serve(socket), "fake-https-session");
                session.setDaemon(true);
                session.start();
            } catch (IOException closed) {
                return;
            }
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            InputStream in = new BufferedInputStream(socket.getInputStream());
            OutputStream out = socket.getOutputStream();
            while (true) {
                String requestLine = readLine(in);
                if (requestLine == null || requestLine.isEmpty()) {
                    return;
                }
                String[] parts = requestLine.split(" ");
                Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                int credentials = 0;
                boolean authorized = false;
                for (String line; !(line = readLine(in)).isEmpty(); ) {
                    int colon = line.indexOf(':');
                    String name = line.substring(0, colon);
                    String value = line.substring(colon + 1).trim();
                    headers.computeIfAbsent(name, k -> new CopyOnWriteArrayList<>()).add(value);
                    if (name.equalsIgnoreCase(headerName)) {
                        credentials++;
                        authorized = Arrays.equals(value.getBytes(StandardCharsets.UTF_8),
                                expected);
                    }
                }
                int length = headers.containsKey("Content-Length")
                        ? Integer.parseInt(headers.get("Content-Length").get(0)) : 0;
                String body = new String(in.readNBytes(length), StandardCharsets.UTF_8);
                boolean ok = authorized && credentials == 1 && parts.length == 3;
                // what is recorded holds no credential - only whether it matched
                headers.remove(headerName);
                received.add(new Received(parts[0], parts.length > 1 ? parts[1] : "",
                        headers, body, ok));
                if (!answer(out, parts[0], parts.length > 1 ? parts[1] : "", ok, body)) {
                    return;
                }
                if (dropSilently) {
                    return;
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // the client went away; the test asserts on what was recorded
        }
    }

    /** @return whether the connection stays open */
    private boolean answer(OutputStream out, String method, String target, boolean ok,
                           String body) throws IOException {
        if (!ok) {
            write(out, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
            return true;
        }
        String full = target.contains("?") ? target.substring(0, target.indexOf('?')) : target;
        String path = full.substring(Math.max(0, full.lastIndexOf('/')));   // after any base path
        String text = method + " " + target + (body.isEmpty() ? "" : " " + body);
        switch (path) {
            case "/chunked" -> {
                write(out, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                        + "Content-Type: text/plain\r\n\r\n"
                        + "5\r\nhello\r\n1;ext=1\r\n \r\n5\r\nworld\r\n0\r\nX-Trailer: t\r\n\r\n");
                return true;
            }
            case "/close" -> {
                write(out, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil the end");
                return false;
            }
            case "/empty" -> {
                write(out, "HTTP/1.1 204 No Content\r\n\r\n");
                return true;
            }
            case "/redirect" -> {
                write(out, "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\n"
                        + "Content-Length: 0\r\n\r\n");
                return true;
            }
            case "/big" -> {
                byte[] big = new byte[200_000];
                Arrays.fill(big, (byte) 'x');
                write(out, "HTTP/1.1 200 OK\r\nContent-Length: " + big.length + "\r\n\r\n");
                out.write(big);
                out.flush();
                return true;
            }
            case "/continue" -> {
                write(out, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                        + "\r\nafter");
                return true;
            }
            case "/missing" -> {
                write(out, "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
                        + "Content-Length: 9\r\n\r\nno orders");
                return true;
            }
            default -> {
                byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
                write(out, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                        + bytes.length + "\r\n\r\n");
                if (!method.toUpperCase(Locale.ROOT).equals("HEAD")) {
                    out.write(bytes);
                }
                out.flush();
                return true;
            }
        }
    }

    private static void write(OutputStream out, String text) throws IOException {
        out.write(text.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    /** A line without CRLF; null at the end. A bare LF is a client bug and ends the session. */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int previous = -1;
        int b;
        while ((b = in.read()) >= 0) {
            if (b == '\n') {
                if (previous != '\r') {
                    throw new IOException("a bare LF from the client");
                }
                byte[] bytes = line.toByteArray();
                return new String(bytes, 0, bytes.length - 1, StandardCharsets.UTF_8);
            }
            line.write(b);
            previous = b;
        }
        return null;
    }

    @Override
    public void close() throws IOException {
        listener.close();
    }
}
