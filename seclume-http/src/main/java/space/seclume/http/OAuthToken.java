package space.seclume.http;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import space.seclume.internal.Base64Off;
import space.seclume.internal.JsonOff;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The access token of the client credentials grant: fetched from the token
 * endpoint with the client secret, kept in native memory, and written into
 * each request as {@code Authorization: Bearer ...} - renewed before it
 * expires, and at once when the API answers 401.
 *
 * <p>Neither secret becomes a heap object on the way:
 *
 * <ul>
 *   <li>the <b>client secret</b> goes from its provider into the token request
 *       in native memory - form-encoded there, and for {@code client-auth=basic}
 *       base64-encoded there as well; even the request's Content-Length is
 *       written there when the secret is in the body, since it would give the
 *       secret's length away;
 *   <li>the <b>access token</b> is read from the token endpoint's answer into
 *       native memory - the answer is decrypted by seclume's TLS into a direct
 *       buffer and parsed there ({@link JsonOff}) - and kept in a shared,
 *       locked {@link SecretScope} until it is replaced or this is closed.
 * </ul>
 *
 * <p>What is on the heap is public: the client id, the scope, the token
 * endpoint's status line and headers, and an error's description.
 */
final class OAuthToken implements BearerSource {

    private static final int MAX_ANSWER = 64 * 1024;
    private static final int MAX_TOKEN = 16 * 1024;
    private static final int MAX_LINE = 16 * 1024;
    private static final long DEFAULT_LIFETIME_SECONDS = 300;
    private static final byte[] HEAD = "Authorization: Bearer "
            .getBytes(StandardCharsets.US_ASCII); // seclume-allow: the header name and scheme; the token follows off the heap

    private final OAuthSettings oauth;
    private final SecretProvider clientSecret;
    private final space.seclume.jwt.SeclumeJwt assertions;   // private_key_jwt only
    private SecretScope token;             // guarded by this
    private long refreshAt;                // System.nanoTime() after which it is renewed
    private boolean closed;

    OAuthToken(OAuthSettings oauth, SecretProvider clientSecret) {
        this.oauth = oauth;
        this.clientSecret = clientSecret;
        this.assertions = oauth.clientAuth == OAuthSettings.ClientAuth.PRIVATE_KEY_JWT
                ? space.seclume.jwt.SeclumeJwt.of(oauth.assertionAlg, oauth.assertionKid,
                        clientSecret)
                : null;
        // The access token is cached until it is due; a checkpoint image
        // must not carry it.
        space.seclume.internal.Checkpoint.register(this, OAuthToken::invalidate);
    }

    /** The header line, CRLF included - with a token renewed first if it is due. */
    @Override
    public void writeHeader(HttpWire wire) throws IOException {
        try (SecretScope line = headerLine()) {
            wire.write(line.segment().asSlice(0, line.length()).asByteBuffer());
        }
    }

    private synchronized SecretScope headerLine() throws IOException {
        if (closed) {
            throw new IllegalStateException("this client is closed");
        }
        if (token == null || System.nanoTime() - refreshAt > 0) {
            refresh();
        }
        int length = HEAD.length + token.length() + 2;
        SecretScope line = SecretScope.allocate(length);
        MemorySegment out = line.segment();
        MemorySegment.copy(HEAD, 0, out, ValueLayout.JAVA_BYTE, 0, HEAD.length);
        MemorySegment.copy(token.segment(), 0, out, HEAD.length, token.length());
        out.set(ValueLayout.JAVA_BYTE, length - 2, (byte) '\r');
        out.set(ValueLayout.JAVA_BYTE, length - 1, (byte) '\n');
        line.length(length);
        return line;
    }

    /** The API refused the token: the next request fetches a new one. */
    @Override
    public synchronized void invalidate() {
        if (token != null) {
            token.close();
            token = null;
        }
    }

    @Override
    public synchronized void close() {
        closed = true;
        invalidate();
        if (assertions != null) {
            assertions.close();
        } else {
            clientSecret.close();
        }
    }

    // ---- the token request ---------------------------------------------------

    private void refresh() throws IOException {
        invalidate();
        String publicForm = "grant_type=client_credentials&client_id=" + form(oauth.clientId)
                + (oauth.scope == null ? "" : "&scope=" + form(oauth.scope))
                + (oauth.resource == null ? "" : "&resource=" + form(oauth.resource))
                + (oauth.audience == null ? "" : "&audience=" + form(oauth.audience));
        String head = "POST " + oauth.path + " HTTP/1.1\r\n"
                + "Host: " + oauth.authority + "\r\n"
                + "User-Agent: seclume-http\r\n"
                + "Accept: application/json\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n"
                + "Connection: close\r\n";
        if (assertions != null) {
            String form = publicForm + "&client_assertion_type="
                    + form("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                    + "&client_assertion=" + assertion();
            try (HttpWire wire = HttpWire.connect(oauth.endpoint)) {
                wire.writeAscii(head + "Content-Length: " + form.length() + "\r\n\r\n" + form);
                readAnswer(wire);
            }
            return;
        }
        try (HttpWire wire = HttpWire.connect(oauth.endpoint);
             SecretScope secret = SecretScope.fromProvider(clientSecret)) {
            wire.writeAscii(head);
            if (oauth.clientAuth == OAuthSettings.ClientAuth.BASIC) {
                basic(wire, secret);
                wire.writeAscii("Content-Length: " + publicForm.length() + "\r\n\r\n"
                        + publicForm);
            } else {
                postBody(wire, secret, publicForm);
            }
            readAnswer(wire);
        }
    }

    /**
     * RFC 7523: a JWT the application signs with its private key - which is
     * held by OpenSSL, never the JVM - for this token endpoint only, valid for
     * five minutes and never twice ({@code jti}). It is a credential for that
     * long and goes onto the heap as the String it is sent as; the key that
     * made it does not.
     */
    private String assertion() {
        long now = java.time.Instant.now().getEpochSecond();
        java.util.Map<String, Object> header = new java.util.LinkedHashMap<>();
        if (oauth.x5tS256 != null) {
            header.put("x5t#S256", oauth.x5tS256);
        }
        java.util.Map<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put("iss", oauth.clientId);
        claims.put("sub", oauth.clientId);
        claims.put("aud", oauth.tokenUrl);
        claims.put("jti", java.util.UUID.randomUUID().toString());
        claims.put("iat", now);
        claims.put("nbf", now);
        claims.put("exp", now + 300);
        return assertions.sign(header, claims);
    }

    /** {@code Authorization: Basic base64(form(id):form(secret))} - RFC 6749 2.3.1. */
    private void basic(HttpWire wire, SecretScope secret) throws IOException {
        byte[] id = (form(oauth.clientId) + ":").getBytes(StandardCharsets.US_ASCII); // seclume-allow: the client id, which is public
        int secretLength = formLength(secret);
        int rawLength = id.length + secretLength;
        try (SecretScope raw = SecretScope.allocate(rawLength)) {
            MemorySegment at = raw.segment();
            MemorySegment.copy(id, 0, at, ValueLayout.JAVA_BYTE, 0, id.length);
            formEncode(secret, at, id.length);
            byte[] prefix = "Authorization: Basic ".getBytes(StandardCharsets.US_ASCII); // seclume-allow: the header name and scheme
            int encoded = Base64Off.encodedLength(rawLength);
            try (SecretScope line = SecretScope.allocate(prefix.length + encoded + 2)) {
                MemorySegment out = line.segment();
                MemorySegment.copy(prefix, 0, out, ValueLayout.JAVA_BYTE, 0, prefix.length);
                int written = Base64Off.encode(at, 0, rawLength, out, prefix.length);
                int end = prefix.length + written;
                out.set(ValueLayout.JAVA_BYTE, end, (byte) '\r');
                out.set(ValueLayout.JAVA_BYTE, end + 1, (byte) '\n');
                wire.write(out.asSlice(0, end + 2).asByteBuffer());
            }
        }
    }

    /**
     * {@code client-auth=post}: the secret in the form body - and so its
     * length in Content-Length, which is written from native memory with it.
     */
    private void postBody(HttpWire wire, SecretScope secret, String publicForm)
            throws IOException {
        byte[] before = (publicForm + "&client_secret=").getBytes(StandardCharsets.US_ASCII); // seclume-allow: the public part of the form
        byte[] lengthName = "Content-Length: ".getBytes(StandardCharsets.US_ASCII); // seclume-allow: a header name
        int bodyLength = before.length + formLength(secret);
        int digits = 1;
        for (int rest = bodyLength / 10; rest > 0; rest /= 10) {
            digits++;
        }
        int total = lengthName.length + digits + 4 + bodyLength;
        try (SecretScope request = SecretScope.allocate(total)) {
            MemorySegment out = request.segment();
            int at = 0;
            MemorySegment.copy(lengthName, 0, out, ValueLayout.JAVA_BYTE, at, lengthName.length);
            at += lengthName.length;
            for (int i = digits - 1, rest = bodyLength; i >= 0; i--, rest /= 10) {
                out.set(ValueLayout.JAVA_BYTE, at + i, (byte) ('0' + rest % 10));
            }
            at += digits;
            for (byte b : new byte[] {'\r', '\n', '\r', '\n'}) {
                out.set(ValueLayout.JAVA_BYTE, at++, b);
            }
            MemorySegment.copy(before, 0, out, ValueLayout.JAVA_BYTE, at, before.length);
            at += before.length;
            formEncode(secret, out, at);
            wire.write(out.asSlice(0, total).asByteBuffer());
        }
    }

    // ---- the answer -----------------------------------------------------------

    private void readAnswer(HttpWire wire) throws IOException {
        String statusLine = wire.readLine(MAX_LINE);
        if (statusLine == null || !statusLine.startsWith("HTTP/1.") || statusLine.length() < 12) {
            throw new IOException("no HTTP answer from the token endpoint "
                    + oauth.authority);
        }
        int status;
        try {
            status = Integer.parseInt(statusLine.substring(9, 12));
        } catch (NumberFormatException e) {
            throw new IOException("a malformed status line from the token endpoint", e);
        }
        long contentLength = -1;
        boolean chunked = false;
        for (String line; !(line = wire.readLine(MAX_LINE)).isEmpty(); ) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).trim();
            if (name.equals("content-length")) {
                try {
                    contentLength = Long.parseLong(value);
                } catch (NumberFormatException e) {
                    throw new IOException("a malformed Content-Length from the token endpoint",
                            e);
                }
            } else if (name.equals("transfer-encoding")
                    && value.toLowerCase(Locale.ROOT).contains("chunked")) {
                chunked = true;
            }
        }
        try (SecretScope answer = SecretScope.allocate(MAX_ANSWER)) {
            int length = chunked ? readChunked(wire, answer.segment())
                    : readFixed(wire, answer.segment(), contentLength);
            if (status != 200) {
                throw refusal(status, answer.segment(), length);
            }
            take(answer.segment(), length);
        }
    }

    private int readFixed(HttpWire wire, MemorySegment into, long contentLength)
            throws IOException {
        if (contentLength > MAX_ANSWER) {
            throw new IOException("the token endpoint's answer is larger than " + MAX_ANSWER
                    + " bytes");
        }
        int limit = contentLength < 0 ? MAX_ANSWER : (int) contentLength;
        int at = 0;
        while (at < limit) {
            int n = wire.read(into, at, limit - at);
            if (n < 0) {
                if (contentLength < 0) {
                    return at;                  // up to the close
                }
                throw new IOException("the token endpoint closed the connection in the "
                        + "middle of its answer");
            }
            at += n;
        }
        return at;
    }

    private int readChunked(HttpWire wire, MemorySegment into) throws IOException {
        int at = 0;
        while (true) {
            String sizeLine = wire.readLine(MAX_LINE);
            if (sizeLine == null) {
                throw new IOException("the token endpoint closed the connection in the "
                        + "middle of its answer");
            }
            int semicolon = sizeLine.indexOf(';');
            int size;
            try {
                size = Integer.parseInt((semicolon >= 0 ? sizeLine.substring(0, semicolon)
                        : sizeLine).trim(), 16);
            } catch (NumberFormatException e) {
                throw new IOException("a malformed chunk from the token endpoint", e);
            }
            if (size == 0) {
                return at;
            }
            if (size < 0 || at + size > MAX_ANSWER) {
                throw new IOException("the token endpoint's answer is larger than "
                        + MAX_ANSWER + " bytes");
            }
            int end = at + size;
            while (at < end) {
                int n = wire.read(into, at, end - at);
                if (n < 0) {
                    throw new IOException("the token endpoint closed the connection in the "
                            + "middle of its answer");
                }
                at += n;
            }
            wire.readLine(MAX_LINE);                    // the CRLF after the chunk
        }
    }

    /** The access token into native memory, and when to renew it. */
    private void take(MemorySegment json, int length) throws IOException {
        String type = publicField(json, length, "token_type");
        if (type != null && !type.equalsIgnoreCase("bearer")) {
            throw new IOException("the token endpoint issued a token of type '" + type
                    + "'; only Bearer tokens are sent");
        }
        SecretScope fresh = SecretScope.allocateShared(MAX_TOKEN);
        try {
            int written = JsonOff.string(json, length, fresh.segment(), "access_token");
            if (written == 0) {
                throw new IOException("the token endpoint's answer has an empty access_token");
            }
            MemorySegment at = fresh.segment();
            for (int i = 0; i < written; i++) {
                byte b = at.get(ValueLayout.JAVA_BYTE, i);
                if (b <= ' ' || b == 127) {
                    throw new IOException("the access token holds a space or control "
                            + "character and cannot go into a header");
                }
            }
            fresh.length(written);
        } catch (JsonOff.NotFound e) {
            fresh.close();
            throw new IOException("the token endpoint's answer has no access_token", e);
        } catch (IOException | RuntimeException e) {
            fresh.close();
            throw e;
        }
        long lifetime = lifetime(json, length);
        long margin = Math.min(60, lifetime / 10);
        refreshAt = System.nanoTime() + Math.max(1, lifetime - margin) * 1_000_000_000L;
        token = fresh;
    }

    /** {@code expires_in}: a number as RFC 6749 says, or a string as older Entra ID sends. */
    private static long lifetime(MemorySegment json, int length) {
        if (!JsonOff.has(json, length, "expires_in")) {
            return DEFAULT_LIFETIME_SECONDS;
        }
        try {
            return Math.max(1, JsonOff.number(json, length, "expires_in"));
        } catch (JsonOff.NotFound notANumber) {
            String text = publicField(json, length, "expires_in");
            try {
                return text == null ? DEFAULT_LIFETIME_SECONDS : Math.max(1, Long.parseLong(text));
            } catch (NumberFormatException e) {
                return DEFAULT_LIFETIME_SECONDS;
            }
        }
    }

    private IOException refusal(int status, MemorySegment json, int length) {
        String error = publicField(json, length, "error");
        String description = publicField(json, length, "error_description");
        return new IOException("the token endpoint " + oauth.authority + " refused the client "
                + oauth.clientId + " (" + status + (error == null ? "" : ", " + error) + ")"
                + (description == null ? "" : ": " + description));
    }

    /** A field of the answer that is not secret - an error, a type, a lifetime. */
    private static String publicField(MemorySegment json, int length, String name) {
        try (SecretScope scratch = SecretScope.allocate(1024)) {
            int n = JsonOff.string(json, length, scratch.segment(), name);
            byte[] bytes = new byte[n];
            MemorySegment.copy(scratch.segment(), ValueLayout.JAVA_BYTE, 0, bytes, 0, n);
            return new String(bytes, StandardCharsets.UTF_8); // seclume-allow: error, error_description, token_type or expires_in - never access_token
        } catch (JsonOff.NotFound | IndexOutOfBoundsException absent) {
            return null;
        }
    }

    // ---- form encoding in native memory -----------------------------------------

    private static boolean unreserved(byte b) {
        return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
                || b == '-' || b == '.' || b == '_' || b == '~';
    }

    private static int formLength(SecretScope secret) {
        MemorySegment at = secret.segment();
        int length = 0;
        for (int i = 0; i < secret.length(); i++) {
            length += unreserved(at.get(ValueLayout.JAVA_BYTE, i)) ? 1 : 3;
        }
        return length;
    }

    private static void formEncode(SecretScope secret, MemorySegment out, long offset) {
        MemorySegment at = secret.segment();
        long to = offset;
        for (int i = 0; i < secret.length(); i++) {
            byte b = at.get(ValueLayout.JAVA_BYTE, i);
            if (unreserved(b)) {
                out.set(ValueLayout.JAVA_BYTE, to++, b);
            } else {
                out.set(ValueLayout.JAVA_BYTE, to++, (byte) '%');
                out.set(ValueLayout.JAVA_BYTE, to++, hex((b >> 4) & 0xf));
                out.set(ValueLayout.JAVA_BYTE, to++, hex(b & 0xf));
            }
        }
    }

    private static byte hex(int nibble) {
        return (byte) (nibble < 10 ? '0' + nibble : 'A' + nibble - 10);
    }

    /** Public values - the client id, a scope. */
    private static String form(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
