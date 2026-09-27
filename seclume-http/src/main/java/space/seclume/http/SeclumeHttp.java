package space.seclume.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * An HTTPS client for one API whose credential - an API key, a bearer token,
 * a Basic password - stays off the heap.
 *
 * <pre>
 * SeclumeHttp api = SeclumeHttp.of(
 *         "https://api.example.com/v1?provider=file&amp;path=/run/secrets/api-token");
 * try (SeclumeHttp.Response response = api.send("GET", "/orders?status=open", Map.of(), null)) {
 *     byte[] json = response.body().readAllBytes();
 * }
 *
 * RestClient rest = RestClient.builder()                      // Spring
 *         .requestFactory(new SeclumeHttpRequestFactory(api))
 *         .baseUrl("https://api.example.com/v1").build();
 * </pre>
 *
 * <p><b>The credential</b> is added by this client and by nothing else: read
 * from the provider for each request, written as a header from native memory
 * into seclume's own TLS 1.3 (see {@link Credential}), and wiped. The
 * application never sets it - a request that does is refused, since the value
 * would be a {@code String} already.
 *
 * <p><b>Only to its own origin.</b> The credential goes to the scheme, host and
 * port of the URL and nowhere else. A request for another origin is refused
 * rather than sent without it, and redirects are not followed: a 3xx comes
 * back as it is.
 *
 * <p><b>What is not off the heap: the requests and responses.</b> Paths,
 * headers and bodies are the application's data. This is the line the JDBC
 * drivers draw too: the password is not a {@code String}, the rows are.
 *
 * <p>HTTP/1.1, with connections kept for reuse ({@code maxIdle},
 * {@code idleTimeout}). A request that finds a kept connection closed by the
 * server is sent again on a new one when its method is idempotent.
 * Thread-safe.
 */
public final class SeclumeHttp implements AutoCloseable {

    private static final int MAX_LINE = 16 * 1024;
    private static final int MAX_HEADERS = 200;
    private static final Set<String> IDEMPOTENT = Set.of("GET", "HEAD", "PUT", "DELETE",
            "OPTIONS", "TRACE");
    private static final Set<String> MANAGED = Set.of("host", "content-length",
            "transfer-encoding", "connection", "upgrade", "te", "trailer", "keep-alive",
            "proxy-authorization", "proxy-connection");

    private final HttpSettings settings;
    private final ArrayDeque<HttpWire> idle = new ArrayDeque<>();
    private boolean closed;

    private SeclumeHttp(HttpSettings settings) {
        this.settings = settings;
    }

    /** One API: {@code https://host[:port][/base]?provider=...} - see {@link HttpSettings}. */
    public static SeclumeHttp of(String url) {
        return new SeclumeHttp(HttpSettings.of(url));
    }

    /**
     * One request. {@code target} is a path with its query, resolved against
     * the URL's base path ({@code /orders?status=open}), or an absolute
     * {@code https://} URI on the same origin.
     *
     * @param headers the application's headers; not the credential's, and
     *                not the ones this client sets itself (Host,
     *                Content-Length, Transfer-Encoding, Connection)
     * @param body    the request body, or null for none
     */
    public Response send(String method, String target, Map<String, List<String>> headers,
                         byte[] body) throws IOException {
        return send(method, URI.create(target), headers, body);
    }

    /** The same with a URI - relative to the base, or absolute on the same origin. */
    public Response send(String method, URI target, Map<String, List<String>> headers,
                         byte[] body) throws IOException {
        String verb = method.toUpperCase(Locale.ROOT);
        if (!HttpSettings.token(verb)) {
            throw new IllegalArgumentException("not an HTTP method: " + method);
        }
        String head = head(verb, requestTarget(target), headers, body);
        boolean retried = false;
        while (true) {
            HttpWire wire = null;
            boolean reused = false;
            try {
                wire = take();
                reused = wire != null;
                if (wire == null) {
                    wire = HttpWire.connect(settings);
                }
                wire.writeAscii(head);
                Credential.write(wire, settings);
                wire.writeAscii("\r\n");
                if (body != null && body.length > 0) {
                    wire.write(ByteBuffer.wrap(body));
                }
                Response response = readResponse(wire, verb);
                if (response == null) {
                    // closed before a byte of the answer: a kept connection the server
                    // had given up on
                    wire.close();
                    if (reused && !retried && IDEMPOTENT.contains(verb)) {
                        retried = true;
                        continue;
                    }
                    throw new IOException(settings.host + " closed the connection without an "
                            + "answer to " + verb);
                }
                return response;
            } catch (IOException | RuntimeException e) {
                if (wire != null) {
                    wire.close();
                }
                if (reused && !retried && IDEMPOTENT.contains(verb)
                        && !(e instanceof IllegalArgumentException)) {
                    retried = true;
                    continue;
                }
                throw e;
            }
        }
    }

    /** The path and query on the wire - and the check that it is this API's origin. */
    private String requestTarget(URI target) {
        String path;
        String query;
        if (target.isAbsolute()) {
            if (!settings.sameOrigin(target)) {
                throw new IllegalArgumentException("this client's credential belongs to https://"
                        + settings.authority() + " and is not sent to " + target.getScheme()
                        + "://" + target.getRawAuthority() + " - use a client made for that "
                        + "URL");
            }
            path = target.getRawPath();
            query = target.getRawQuery();
        } else {
            if (target.getRawAuthority() != null) {
                throw new IllegalArgumentException("a scheme-relative URI (//host/...) is not "
                        + "taken; give a path or an https:// URI");
            }
            String relative = target.getRawPath() == null ? "" : target.getRawPath();
            path = settings.basePath + (relative.startsWith("/") || relative.isEmpty() ? ""
                    : "/") + relative;
            query = target.getRawQuery();
        }
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        String line = query == null ? path : path + "?" + query;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c <= ' ' || c >= 127) {
                throw new IllegalArgumentException("the request target has a space, control "
                        + "or non-ASCII character in it - encode it: " + line);
            }
        }
        return line;
    }

    /** The request line and headers - everything but the credential and the blank line. */
    private String head(String verb, String target, Map<String, List<String>> headers,
                        byte[] body) {
        StringBuilder head = new StringBuilder(256); // seclume-allow: the request line and the application's headers, no credential
        head.append(verb).append(' ').append(target).append(" HTTP/1.1\r\n");
        head.append("Host: ").append(settings.authority()).append("\r\n");
        boolean agent = false;
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            String name = header.getKey();
            String lower = name.toLowerCase(Locale.ROOT);
            if (!HttpSettings.token(name)) {
                throw new IllegalArgumentException("not a header name: '" + name + "'");
            }
            if (lower.equals(settings.headerName.toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException("the request sets " + name + " itself; "
                        + "that header is this client's, from the secret provider - a value "
                        + "set by the application is a String on the heap already");
            }
            if (MANAGED.contains(lower)) {
                throw new IllegalArgumentException(name + " is set by the client, not by the "
                        + "request");
            }
            agent |= lower.equals("user-agent");
            for (String value : header.getValue()) {
                if (!HttpSettings.printable(value)) {
                    throw new IllegalArgumentException("the value of " + name + " holds a line "
                            + "break or control character");
                }
                head.append(name).append(": ").append(value).append("\r\n");
            }
        }
        if (!agent) {
            head.append("User-Agent: seclume-http\r\n");
        }
        if (body != null || verb.equals("POST") || verb.equals("PUT") || verb.equals("PATCH")) {
            head.append("Content-Length: ").append(body == null ? 0 : body.length).append("\r\n");
        }
        return head.toString();
    }

    /** The response head, and a body stream that gives the connection back when read. */
    private Response readResponse(HttpWire wire, String verb) throws IOException {
        while (true) {
            String statusLine = wire.readLine(MAX_LINE);
            if (statusLine == null) {
                return null;
            }
            if (!statusLine.startsWith("HTTP/1.") || statusLine.length() < 12
                    || statusLine.charAt(8) != ' ') {
                throw new IOException("not an HTTP/1.x answer from " + settings.host + ": "
                        + abbreviate(statusLine));
            }
            int status = parseStatus(statusLine);
            String reason = statusLine.length() > 13 ? statusLine.substring(13) : "";
            boolean http10 = statusLine.startsWith("HTTP/1.0");
            TreeMap<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            int count = 0;
            for (String line; !(line = wire.readLine(MAX_LINE)).isEmpty(); ) {
                if (++count > MAX_HEADERS) {
                    throw new IOException(settings.host + " sent more than " + MAX_HEADERS
                            + " headers");
                }
                int colon = line.indexOf(':');
                if (colon <= 0) {
                    throw new IOException("a malformed header from " + settings.host + ": "
                            + abbreviate(line));
                }
                headers.computeIfAbsent(line.substring(0, colon).trim(), k -> new ArrayList<>())
                        .add(line.substring(colon + 1).trim());
            }
            if (status == 101) {
                throw new IOException(settings.host + " switched protocols (101), which this "
                        + "client does not do");
            }
            if (status >= 100 && status < 200) {
                continue;                          // 100 Continue, 103 Early Hints
            }
            boolean keepAlive = !http10 && !hasToken(headers, "Connection", "close")
                    || http10 && hasToken(headers, "Connection", "keep-alive");
            Body body;
            if (verb.equals("HEAD") || status == 204 || status == 304) {
                body = new Body(wire, 0, false, keepAlive);
            } else if (hasToken(headers, "Transfer-Encoding", "chunked")) {
                body = new Body(wire, -1, true, keepAlive);
            } else if (headers.containsKey("Content-Length")) {
                long length = contentLength(headers.get("Content-Length"));
                body = new Body(wire, length, false, keepAlive);
            } else {
                body = new Body(wire, Long.MAX_VALUE, false, false);   // until the server closes
            }
            if (body.finished()) {
                body.release();
            }
            return new Response(status, reason, Collections.unmodifiableMap(headers), body);
        }
    }

    private int parseStatus(String statusLine) throws IOException {
        int status = 0;
        for (int i = 9; i < 12; i++) {
            char c = statusLine.charAt(i);
            if (c < '0' || c > '9') {
                throw new IOException("a malformed status line from " + settings.host + ": "
                        + abbreviate(statusLine));
            }
            status = status * 10 + (c - '0');
        }
        return status;
    }

    private long contentLength(List<String> values) throws IOException {
        long length = -1;
        for (String value : values) {
            for (String part : value.split(",")) {
                long parsed;
                try {
                    parsed = Long.parseLong(part.trim());
                } catch (NumberFormatException e) {
                    throw new IOException("a malformed Content-Length from " + settings.host, e);
                }
                if (parsed < 0 || length >= 0 && parsed != length) {
                    throw new IOException("a malformed Content-Length from " + settings.host);
                }
                length = parsed;
            }
        }
        return length;
    }

    private static boolean hasToken(Map<String, List<String>> headers, String name,
                                    String token) {
        List<String> values = headers.get(name);
        if (values == null) {
            return false;
        }
        for (String value : values) {
            for (String part : value.split(",")) {
                if (part.trim().equalsIgnoreCase(token)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String abbreviate(String text) {
        return text.length() > 120 ? text.substring(0, 120) + "..." : text;
    }

    // ---- the pool -------------------------------------------------------------

    private synchronized HttpWire take() {
        if (closed) {
            throw new IllegalStateException("this client is closed");
        }
        while (!idle.isEmpty()) {
            HttpWire wire = idle.pollLast();
            if (wire.isOpen() && !wire.staleAfter(settings.idleTimeoutMillis)) {
                return wire;
            }
            wire.close();
        }
        return null;
    }

    private void giveBack(HttpWire wire) {
        synchronized (this) {
            if (!closed && idle.size() < settings.maxIdle && wire.isOpen() && wire.drained()) {
                wire.idle();
                idle.addLast(wire);
                return;
            }
        }
        wire.close();
    }

    /** Closes the kept connections; a response still being read keeps its own. */
    @Override
    public void close() {
        List<HttpWire> all;
        synchronized (this) {
            closed = true;
            all = new ArrayList<>(idle);
            idle.clear();
        }
        all.forEach(HttpWire::close);
        settings.secret.close();
    }

    @Override
    public String toString() {
        return "SeclumeHttp[" + settings + "]";
    }

    // ---- the response ---------------------------------------------------------

    /** One response: status, headers and a body read from the connection. Close it. */
    public static final class Response implements AutoCloseable {

        private final int status;
        private final String reason;
        private final Map<String, List<String>> headers;
        private final Body body;

        private Response(int status, String reason, Map<String, List<String>> headers,
                         Body body) {
            this.status = status;
            this.reason = reason;
            this.headers = headers;
            this.body = body;
        }

        public int status() {
            return status;
        }

        public String reason() {
            return reason;
        }

        /** Header names are case-insensitive. */
        public Map<String, List<String>> headers() {
            return headers;
        }

        /** The first value of a header, or null. */
        public String header(String name) {
            List<String> values = headers.get(name);
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        /** The body; read to its end, it gives the connection back for reuse. */
        public InputStream body() {
            return body;
        }

        @Override
        public void close() throws IOException {
            body.close();
        }

        @Override
        public String toString() {
            return "Response[" + status + " " + reason + "]";
        }
    }

    /**
     * A body of known length, chunked, or up to the end of the connection. At
     * its end the connection goes back to the pool when it may be reused;
     * closed before that, the connection is closed.
     */
    private final class Body extends InputStream {

        private final HttpWire wire;
        private final boolean chunked;
        private final boolean keepAlive;
        private long remaining;           // in this chunk, or of the whole body
        private boolean done;
        private boolean released;

        Body(HttpWire wire, long length, boolean chunked, boolean keepAlive) {
            this.wire = wire;
            this.chunked = chunked;
            this.keepAlive = keepAlive;
            this.remaining = chunked ? 0 : length;
            this.done = !chunked && length == 0;
        }

        boolean finished() {
            return done;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] into, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            if (done) {
                release();
                return -1;
            }
            if (chunked && remaining == 0 && !nextChunk()) {
                return -1;
            }
            int n = wire.read(into, offset, (int) Math.min(length, remaining));
            if (n < 0) {
                if (remaining == Long.MAX_VALUE && !chunked) {
                    done = true;                 // the end of a body without a length
                    release();
                    return -1;
                }
                wire.close();
                released = true;
                throw new IOException(settings.host + " closed the connection in the middle "
                        + "of the response body");
            }
            if (remaining != Long.MAX_VALUE) {
                remaining -= n;
            }
            if (!chunked && remaining == 0) {
                done = true;
                release();
            }
            return n;
        }

        /** The next chunk's size; false at the last one, after its trailers. */
        private boolean nextChunk() throws IOException {
            if (remaining == 0 && startedChunks) {
                String end = wire.readLine(MAX_LINE);          // the CRLF after a chunk
                if (end == null || !end.isEmpty()) {
                    throw new IOException("a malformed chunk from " + settings.host);
                }
            }
            startedChunks = true;
            String sizeLine = wire.readLine(MAX_LINE);
            if (sizeLine == null) {
                throw new IOException(settings.host + " closed the connection in the middle "
                        + "of a chunked body");
            }
            int semicolon = sizeLine.indexOf(';');
            String hex = (semicolon >= 0 ? sizeLine.substring(0, semicolon) : sizeLine).trim();
            long size;
            try {
                size = Long.parseLong(hex, 16);
            } catch (NumberFormatException e) {
                throw new IOException("a malformed chunk size from " + settings.host, e);
            }
            if (size < 0) {
                throw new IOException("a malformed chunk size from " + settings.host);
            }
            if (size == 0) {
                for (String trailer; (trailer = wire.readLine(MAX_LINE)) != null
                        && !trailer.isEmpty(); ) {
                    // trailers are not kept
                }
                done = true;
                release();
                return false;
            }
            remaining = size;
            return true;
        }

        private boolean startedChunks;

        void release() {
            if (released) {
                return;
            }
            released = true;
            if (keepAlive) {
                giveBack(wire);
            } else {
                wire.close();
            }
        }

        @Override
        public void close() {
            if (!released) {
                if (done) {
                    release();
                } else {
                    // not read to its end: what is left cannot be told from the next
                    // response, so the connection is not reused
                    released = true;
                    wire.close();
                }
            }
        }
    }
}
