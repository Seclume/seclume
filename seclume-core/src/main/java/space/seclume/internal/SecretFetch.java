package space.seclume.internal;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * One HTTP request whose answer is allowed to contain a secret.
 *
 * <p>Every secret manager worth connecting to speaks HTTPS and answers in
 * JSON, and every HTTP client in the JDK hands that answer over as a
 * {@code String} or a {@code byte[]}. {@code HttpClient} does it three times
 * over - once in its own buffers, once in the {@code BodyHandler}, once in
 * whatever JSON library reads it - and none of those copies can be wiped. For
 * a Vault or a Key Vault response, which contains the password in clear text,
 * that is the whole guarantee gone before the secret has even been looked at.
 *
 * <p>So this exists: as much HTTP/1.1 as a secret manager needs and no more.
 * One request, one response, the body landing <b>directly in a caller-owned
 * segment</b> of native memory. No connection reuse, no redirects, no
 * compression, no cookies - a credential fetch is rare, small and must be
 * simple enough to read in one sitting.
 *
 * <p>The request line and headers are ordinary text. They carry a path and a
 * token header - and the token, which <i>is</i> secret, is written into the
 * request buffer from a segment rather than being concatenated into a
 * {@code String}. That request buffer is the caller's to wipe.
 *
 * <h2>What it does not do</h2>
 *
 * <p>No proxy support, no HTTP/2, no keep-alive, and only {@code Content-Length}
 * or {@code chunked} bodies. A secret manager that needs more than that is one
 * seclume should talk to through a different provider rather than growing a
 * browser in here.
 */
public final class SecretFetch {

    /** As much of an answer as any credential response has a right to be. */
    public static final int MAX_RESPONSE = 256 * 1024;

    private SecretFetch() {
    }

    /** What the server said, with the body already in the caller's segment. */
    public record Response(int status, int bodyLength) {

        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    /**
     * Sends a request and writes the response body into {@code body}.
     *
     * @param host    the name to dial and to check the certificate against
     * @param port    usually 443
     * @param verify  whether to check the certificate; {@code false} only for
     *                a development Vault, and the caller has to say so
     * @param method  {@code GET} or {@code POST}
     * @param path    the request target, already encoded
     * @param headers header names and values, none of them secret
     * @param secretHeaders headers whose <b>value</b> is a secret and comes
     *                from native memory - a Vault token, typically
     * @param requestBody the request body, or {@code null}
     * @param body    where the response body goes; the caller wipes it
     */
    public static Response send(String host, int port, boolean verify, int timeoutMillis,
            String method, String path, Map<String, String> headers,
            List<SecretHeader> secretHeaders, String requestBody, MemorySegment body)
            throws IOException {

        try (Transport socket = SocketTransport.connect(host, port, timeoutMillis);
             TlsChannel tls = TlsChannel.create(socket, host, port, verify)) {
            tls.handshake();

            ByteBuffer request = ByteBuffer.allocateDirect(8 * 1024);
            writeRequest(request, host, method, path, headers, secretHeaders, requestBody);
            request.flip();
            try {
                while (request.hasRemaining()) {
                    tls.write(request);
                }
            } finally {
                // The token was in here. Direct memory, not the heap, but it
                // is still a copy of a secret and it is finished with.
                wipe(request);
            }
            return readResponse(tls::read, body);
        }
    }

    /**
     * The same over plain HTTP - for the one kind of server that has no TLS
     * and is right not to.
     *
     * <p>A cloud's instance metadata service answers on a link-local address,
     * {@code 169.254.169.254}, and on nothing else: the packet never leaves
     * the host it is running on, and there is no certificate to check because
     * there is no network to be attacked across. Azure's IMDS and Google's
     * metadata server both speak plain HTTP there, and both hand out the
     * workload's access token.
     *
     * <p><b>Refused for any other address.</b> The address the name resolves
     * to is checked, not the name, and it has to be link-local - or loopback,
     * which is the same machine and is what a test uses. A token fetched over
     * plain HTTP from anywhere else is a token given away, and a
     * configuration that points this at a real host by mistake must fail
     * rather than work.
     */
    public static Response sendLinkLocal(String host, int port, int timeoutMillis,
            String method, String path, Map<String, String> headers, MemorySegment body)
            throws IOException {
        return sendLinkLocal(host, port, timeoutMillis, method, path, headers, List.of(), body);
    }

    /** The same, with headers whose values must not become a {@code String}. */
    public static Response sendLinkLocal(String host, int port, int timeoutMillis,
            String method, String path, Map<String, String> headers,
            List<SecretHeader> secretHeaders, MemorySegment body) throws IOException {
        java.net.InetAddress address = java.net.InetAddress.getByName(host);
        if (!address.isLinkLocalAddress() && !address.isLoopbackAddress()) {
            throw new IOException("refusing plain HTTP to " + host + " (" + address.getHostAddress()
                    + "): only a link-local metadata service may be asked without TLS");
        }
        try (Transport socket = SocketTransport.connect(address.getHostAddress(), port,
                timeoutMillis)) {
            ByteBuffer request = ByteBuffer.allocateDirect(8 * 1024);
            writeRequest(request, host, method, path, headers, secretHeaders, null);
            request.flip();
            while (request.hasRemaining()) {
                socket.write(request);
            }
            return readResponse(socket::read, body);
        }
    }

    /** Where a response is read from - a TLS channel or, for metadata, the bare socket. */
    @FunctionalInterface
    private interface Source {
        int read(ByteBuffer into) throws IOException;
    }

    /** A header whose value must not become a {@code String}. */
    public record SecretHeader(String name, MemorySegment value, int length) {
    }

    private static void writeRequest(ByteBuffer request, String host, String method, String path,
            Map<String, String> headers, List<SecretHeader> secretHeaders, String body) {
        ascii(request, method + " " + path + " HTTP/1.1\r\n");
        ascii(request, "Host: " + host + "\r\n");
        ascii(request, "Connection: close\r\n");
        ascii(request, "Accept: application/json\r\n");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            ascii(request, header.getKey() + ": " + header.getValue() + "\r\n");
        }
        for (SecretHeader header : secretHeaders) {
            ascii(request, header.name() + ": ");
            for (int i = 0; i < header.length(); i++) {
                request.put(header.value().get(ValueLayout.JAVA_BYTE, i));
            }
            ascii(request, "\r\n");
        }
        if (body != null) {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8); // seclume-allow: request bodies here carry no secret - tokens travel as secret headers
            // The caller's own Content-Type wins, and only one is sent: AWS
            // joins repeated headers into one value, so an added
            // "application/json" beside the signed "application/x-amz-json-1.1"
            // broke every Secrets Manager signature (found live, 26.09.2026).
            boolean typed = headers.keySet().stream()
                    .anyMatch(name -> name.equalsIgnoreCase("Content-Type"));
            if (!typed) {
                ascii(request, "Content-Type: application/json\r\n");
            }
            ascii(request, "Content-Length: " + bytes.length + "\r\n\r\n");
            request.put(bytes);
        } else {
            ascii(request, "\r\n");
        }
    }

    /**
     * Reads status line, headers and body.
     *
     * <p>Headers are parsed byte by byte out of a direct buffer rather than
     * split out of a {@code String}, because the boundary between "headers" and
     * "body" is exactly where a secret starts and a parser that materialised
     * the whole response first would have defeated the point before reaching
     * this comment.
     */
    private static Response readResponse(Source tls, MemorySegment body) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocateDirect(MAX_RESPONSE);
        try {
            while (buffer.hasRemaining() && !complete(buffer)) {
                if (tls.read(buffer) < 0) {
                    break;                      // the server closed; parse what came
                }
            }
            buffer.flip();
            int headerEnd = headerEnd(buffer);
            if (headerEnd < 0) {
                throw new IOException("the secret manager sent no complete HTTP response");
            }
            int status = status(buffer);
            int length = chunked(buffer, headerEnd)
                    ? dechunk(buffer, headerEnd, body)
                    : copyBody(buffer, headerEnd, body);
            return new Response(status, length);
        } finally {
            wipe(buffer);
        }
    }

    /**
     * Whether everything promised has arrived; a short read just loops again.
     *
     * <p>Takes the buffer as it is being filled and looks at a flipped
     * duplicate, so that every other method here can assume a flipped buffer
     * and read absolutely up to {@code limit()}. Mixing the two conventions in
     * one parser is how an off-by-one gets into a security-relevant path.
     */
    private static boolean complete(ByteBuffer filling) {
        ByteBuffer view = filling.duplicate();
        view.flip();
        int headerEnd = headerEnd(view);
        if (headerEnd < 0) {
            return false;
        }
        if (chunked(view, headerEnd)) {
            return endsWithTerminalChunk(view);
        }
        int declared = contentLength(view, headerEnd);
        return declared >= 0 && view.limit() - headerEnd >= declared;
    }

    private static int status(ByteBuffer buffer) throws IOException {
        // "HTTP/1.1 200 OK" - the three digits after the first space.
        int space = indexOf(buffer, (byte) ' ', 0, Math.min(buffer.limit(), 64));
        if (space < 0 || space + 4 > buffer.limit()) {
            throw new IOException("the secret manager sent no HTTP status line");
        }
        int status = 0;
        for (int i = space + 1; i < space + 4; i++) {
            int digit = buffer.get(i) - '0';
            if (digit < 0 || digit > 9) {
                throw new IOException("the secret manager sent a malformed HTTP status line");
            }
            status = status * 10 + digit;
        }
        return status;
    }

    private static int copyBody(ByteBuffer buffer, int from, MemorySegment body)
            throws IOException {
        int length = buffer.limit() - from;
        int declared = contentLength(buffer, from);
        if (declared >= 0) {
            length = Math.min(length, declared);
        }
        if (length > body.byteSize()) {
            throw new IOException("the response is " + length + " bytes and does not fit into "
                    + body.byteSize());
        }
        for (int i = 0; i < length; i++) {
            body.set(ValueLayout.JAVA_BYTE, i, buffer.get(from + i));
        }
        return length;
    }

    /** {@code Transfer-Encoding: chunked} - Vault uses it for larger answers. */
    private static int dechunk(ByteBuffer buffer, int from, MemorySegment body)
            throws IOException {
        int at = from;
        int written = 0;
        while (at < buffer.limit()) {
            int lineEnd = indexOfCrLf(buffer, at);
            if (lineEnd < 0) {
                throw new IOException("a chunk header never ended");
            }
            int size = 0;
            for (int i = at; i < lineEnd; i++) {
                int digit = Character.digit(buffer.get(i), 16);
                if (digit < 0) {
                    break;                      // chunk extension after the size
                }
                size = size * 16 + digit;
            }
            at = lineEnd + 2;
            if (size == 0) {
                return written;
            }
            if (written + size > body.byteSize() || at + size > buffer.limit()) {
                throw new IOException("a chunked response does not fit or is truncated");
            }
            for (int i = 0; i < size; i++) {
                body.set(ValueLayout.JAVA_BYTE, written + i, buffer.get(at + i));
            }
            written += size;
            at += size + 2;                     // past the chunk and its CRLF
        }
        throw new IOException("a chunked response ended without its terminal chunk");
    }

    private static boolean endsWithTerminalChunk(ByteBuffer buffer) {
        int limit = buffer.limit();
        if (limit < 5) {
            return false;
        }
        return buffer.get(limit - 5) == '0' && buffer.get(limit - 4) == '\r'
                && buffer.get(limit - 3) == '\n' && buffer.get(limit - 2) == '\r'
                && buffer.get(limit - 1) == '\n';
    }

    private static boolean chunked(ByteBuffer buffer, int headerEnd) {
        return headerValue(buffer, headerEnd, "transfer-encoding") != null;
    }

    private static int contentLength(ByteBuffer buffer, int headerEnd) {
        String value = headerValue(buffer, headerEnd, "content-length");
        if (value == null) {
            return -1;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException notANumber) {
            return -1;
        }
    }

    /**
     * A header's value, lower-cased name, searched in the header block only.
     *
     * <p>Header names and the two values ever asked for here - a length and an
     * encoding - are not secrets, so they may be {@code String}s. The body
     * never passes through this method.
     */
    private static String headerValue(ByteBuffer buffer, int headerEnd, String name) {
        for (int at = 0; at < headerEnd; ) {
            int lineEnd = indexOfCrLf(buffer, at);
            if (lineEnd < 0 || lineEnd > headerEnd) {
                return null;
            }
            int colon = indexOf(buffer, (byte) ':', at, lineEnd);
            if (colon > 0 && matchesIgnoringCase(buffer, at, colon, name)) {
                StringBuilder value = new StringBuilder(lineEnd - colon);
                for (int i = colon + 1; i < lineEnd; i++) {
                    value.append((char) (buffer.get(i) & 0xff));
                }
                return value.toString();
            }
            at = lineEnd + 2;
        }
        return null;
    }

    private static boolean matchesIgnoringCase(ByteBuffer buffer, int from, int to, String name) {
        if (to - from != name.length()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            if (Character.toLowerCase((char) (buffer.get(from + i) & 0xff)) != name.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    /** The position just after the blank line that ends the headers, in a flipped buffer. */
    private static int headerEnd(ByteBuffer buffer) {
        int limit = buffer.limit();
        for (int i = 0; i + 3 < limit; i++) {
            if (buffer.get(i) == '\r' && buffer.get(i + 1) == '\n'
                    && buffer.get(i + 2) == '\r' && buffer.get(i + 3) == '\n') {
                return i + 4;
            }
        }
        return -1;
    }

    private static int indexOfCrLf(ByteBuffer buffer, int from) {
        for (int i = from; i + 1 < buffer.limit(); i++) {
            if (buffer.get(i) == '\r' && buffer.get(i + 1) == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static int indexOf(ByteBuffer buffer, byte value, int from, int to) {
        for (int i = from; i < to; i++) {
            if (buffer.get(i) == value) {
                return i;
            }
        }
        return -1;
    }

    private static void ascii(ByteBuffer buffer, String text) {
        for (int i = 0; i < text.length(); i++) {
            buffer.put((byte) text.charAt(i));
        }
    }

    /** Direct memory is not the heap, but a copy of a secret is still a copy. */
    private static void wipe(ByteBuffer buffer) {
        buffer.clear();
        while (buffer.hasRemaining()) {
            buffer.put((byte) 0);
        }
    }
}
