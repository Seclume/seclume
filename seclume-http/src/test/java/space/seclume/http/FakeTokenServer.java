package space.seclume.http;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

/**
 * An OAuth 2.0 token endpoint for the tests (the JDK's TLS 1.3): the client
 * credentials grant with the secret in Basic or in the form, checked against
 * what it was given; each grant issues a new token, which {@link #valid} then
 * holds for the API server to accept.
 */
final class FakeTokenServer implements AutoCloseable {

    // what it expects and how it answers
    String clientId = "app-1";
    String clientSecret = "s3cr:t/+&=ü";
    String tokenPrefix = "at-";
    /** {@code expires_in} as a JSON value - a number, or a string as older Entra ID sends. */
    String expiresIn = "3600";
    boolean chunked;
    String tokenType = "Bearer";

    // what it did
    final Set<String> valid = ConcurrentHashMap.newKeySet();
    final List<Map<String, String>> grants = new CopyOnWriteArrayList<>();
    final List<String> clientAuths = new CopyOnWriteArrayList<>();
    final AtomicInteger issued = new AtomicInteger();

    private final SSLServerSocket listener;
    private Thread acceptor;

    FakeTokenServer(SSLContext tls) throws IOException {
        listener = (SSLServerSocket) tls.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        listener.setEnabledProtocols(new String[] {"TLSv1.3"});
    }

    synchronized int port() {
        if (acceptor == null) {
            acceptor = new Thread(this::accept, "fake-token");
            acceptor.setDaemon(true);
            acceptor.start();
        }
        return listener.getLocalPort();
    }

    private void accept() {
        while (!listener.isClosed()) {
            try {
                Socket socket = listener.accept();
                Thread session = new Thread(() -> serve(socket), "fake-token-session");
                session.setDaemon(true);
                session.start();
            } catch (IOException closed) {
                return;
            }
        }
    }

    private void serve(Socket socket) {
        try (socket; InputStream in = new BufferedInputStream(socket.getInputStream())) {
            OutputStream out = socket.getOutputStream();
            String requestLine = readLine(in);
            if (requestLine == null) {
                return;
            }
            Map<String, String> headers = new LinkedHashMap<>();
            for (String line; !(line = readLine(in)).isEmpty(); ) {
                int colon = line.indexOf(':');
                headers.put(line.substring(0, colon).trim().toLowerCase(),
                        line.substring(colon + 1).trim());
            }
            int length = Integer.parseInt(headers.getOrDefault("content-length", "0"));
            String body = new String(in.readNBytes(length), StandardCharsets.UTF_8);
            Map<String, String> form = new LinkedHashMap<>();
            for (String pair : body.split("&")) {
                int equals = pair.indexOf('=');
                form.put(URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
            String id;
            String secret;
            String authorization = headers.get("authorization");
            if (authorization != null && authorization.startsWith("Basic ")) {
                String decoded = new String(Base64.getDecoder().decode(
                        authorization.substring(6)), StandardCharsets.UTF_8);
                int colon = decoded.indexOf(':');
                id = URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8);
                secret = URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8);
                clientAuths.add("basic");
            } else {
                id = form.get("client_id");
                secret = form.remove("client_secret");
                clientAuths.add(secret == null ? "none" : "post");
            }
            form.remove("client_secret");
            grants.add(form);
            boolean ok = requestLine.startsWith("POST ")
                    && "client_credentials".equals(form.get("grant_type"))
                    && clientId.equals(id) && clientSecret.equals(secret)
                    && headers.getOrDefault("content-type", "")
                            .startsWith("application/x-www-form-urlencoded");
            if (!ok) {
                answer(out, 401, "{\"error\":\"invalid_client\",\"error_description\":"
                        + "\"AADSTS7000215: Invalid client secret provided.\"}");
                return;
            }
            String token = tokenPrefix + issued.incrementAndGet();
            valid.add("Bearer " + token);
            answer(out, 200, "{\"token_type\":\"" + tokenType + "\",\"expires_in\":" + expiresIn
                    + ",\"ext_expires_in\":3600,\"access_token\":\"" + token + "\"}");
        } catch (IOException | RuntimeException ignored) {
            // the test asserts on what was recorded
        }
    }

    private void answer(OutputStream out, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + status + (status == 200 ? " OK" : " Unauthorized")
                + "\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n";
        if (chunked) {
            int half = bytes.length / 2;
            out.write((head + "Transfer-Encoding: chunked\r\n\r\n"
                    + Integer.toHexString(half) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(bytes, 0, half);
            out.write(("\r\n" + Integer.toHexString(bytes.length - half) + "\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.write(bytes, half, bytes.length - half);
            out.write("\r\n0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        } else {
            out.write((head + "Content-Length: " + bytes.length + "\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.write(bytes);
        }
        out.flush();
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) >= 0) {
            if (b == '\n') {
                byte[] bytes = line.toByteArray();
                int end = bytes.length > 0 && bytes[bytes.length - 1] == '\r'
                        ? bytes.length - 1 : bytes.length;
                return new String(bytes, 0, end, StandardCharsets.UTF_8);
            }
            line.write(b);
        }
        return null;
    }

    @Override
    public void close() throws IOException {
        listener.close();
    }
}
