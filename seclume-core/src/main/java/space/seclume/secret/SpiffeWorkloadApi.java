package space.seclume.secret;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import space.seclume.crypto.PrivateSigningKey;

/**
 * An X.509-SVID from the SPIFFE Workload API - a SPIRE agent's socket - with
 * its private key kept where it arrives: in native memory.
 *
 * <p>The Workload API is gRPC, and its answer carries the private key in a
 * protobuf field ({@code x509_svid_key}, PKCS#8 DER). Every SPIFFE library
 * reads that answer into a {@code byte[]} and makes a {@code PrivateKey} of
 * it - the key on the heap for as long as the SVID lives. Here the answer is
 * read off the socket straight into locked native memory, the protobuf is
 * walked where it landed, and the key bytes go from there to OpenSSL or CNG
 * ({@link PrivateSigningKey#decode}); the buffer is zeroed after. The
 * certificates and the trust bundle are public and become ordinary objects.
 *
 * <p>The transport is the smallest HTTP/2 a unary call needs, over the Unix
 * socket with prior knowledge: the preface, SETTINGS, one HEADERS with every
 * field a plain literal, one empty request message, and frames read until
 * the first response message is whole. {@code FetchX509SVID} is a stream: a
 * single call ({@link #fetchX509Svid}) takes its first message and closes;
 * {@link #watchX509Svids} keeps the stream open and hands over every message
 * the agent pushes - a rotated SVID, a changed bundle - the moment it comes,
 * opening the flow-control window again as it reads.
 *
 * <p>An answer carries the bundles of federated trust domains as well
 * ({@code federated_bundles}); they come with each SVID, so that a peer of
 * another trust domain is checked against that domain's CAs.
 */
public final class SpiffeWorkloadApi {

    /** Where the socket is named, by the SPIFFE specification. */
    public static final String SOCKET_VARIABLE = "SPIFFE_ENDPOINT_SOCKET";

    private static final byte[] PREFACE =
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII); // seclume-allow: the HTTP/2 preface - no secret
    private static final int DATA = 0x0;
    private static final int HEADERS = 0x1;
    private static final int RST_STREAM = 0x3;
    private static final int SETTINGS = 0x4;
    private static final int PING = 0x6;
    private static final int GOAWAY = 0x7;
    private static final int WINDOW_UPDATE = 0x8;
    private static final int END_STREAM = 0x1;
    private static final int ACK = 0x1;
    private static final int END_HEADERS = 0x4;
    private static final int PADDED = 0x8;
    /** An answer larger than this is not an SVID - a chain, a key, a bundle are a few KiB. */
    private static final int MAX_ANSWER = 256 * 1024;
    private static final int WINDOW = 1 << 20;

    private final Path socket;
    private final int timeoutMillis;

    /**
     * @param socket the Workload API's Unix socket; {@code null} for the one
     *               {@code SPIFFE_ENDPOINT_SOCKET} names
     */
    public SpiffeWorkloadApi(Path socket, int timeoutMillis) {
        this.socket = socket != null ? socket : fromEnvironment();
        this.timeoutMillis = timeoutMillis;
    }

    /** {@code unix:///run/spire/agent.sock}, {@code unix:/run/...} or a plain path. */
    public static Path socketOf(String address) {
        String value = address.trim();
        if (value.startsWith("unix://")) {
            value = value.substring("unix://".length());
        } else if (value.startsWith("unix:")) {
            value = value.substring("unix:".length());
        } else if (value.contains("://")) {
            throw new IllegalArgumentException("the Workload API is reached over a Unix "
                    + "socket here, not " + address);
        }
        if (value.isEmpty()) {
            throw new IllegalArgumentException("no socket path in " + address);
        }
        return Path.of(value);
    }

    /**
     * A {@code timeout-millis} setting: a positive number of milliseconds,
     * {@code fallback} when it is left out.
     */
    public static int timeoutMillis(String setting, String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            int millis = Integer.parseInt(value.trim());
            if (millis > 0) {
                return millis;
            }
        } catch (NumberFormatException e) {
            // said below, with the setting's name
        }
        throw new IllegalArgumentException(setting + " is how many milliseconds a call to the "
                + "Workload API may take, a positive whole number - not " + value);
    }

    private static Path fromEnvironment() {
        String named = System.getenv(SOCKET_VARIABLE); // seclume-allow: the socket's path, which is no secret
        if (named == null || named.isBlank()) {
            throw new IllegalArgumentException("no Workload API socket: set "
                    + SOCKET_VARIABLE + " or give the socket's path");
        }
        return socketOf(named);
    }

    /** The socket asked. */
    public Path socket() {
        return socket;
    }

    /**
     * An SVID: its SPIFFE ID, the certificate chain (leaf first), the trust
     * bundle of its domain, and its key - in OpenSSL or CNG, the caller's to
     * close.
     */
    public record X509Svid(String spiffeId, List<X509Certificate> chain,
            List<X509Certificate> bundle, PrivateSigningKey key,
            Map<String, List<X509Certificate>> federatedBundles) {

        public X509Svid {
            chain = List.copyOf(chain);
            bundle = List.copyOf(bundle);
            federatedBundles = Map.copyOf(federatedBundles);
        }

        /** An SVID of no federation. */
        public X509Svid(String spiffeId, List<X509Certificate> chain,
                List<X509Certificate> bundle, PrivateSigningKey key) {
            this(spiffeId, chain, bundle, key, Map.of());
        }

        /** The trust domain its SPIFFE ID names. */
        public String trustDomain() {
            return SpiffeWorkloadApi.trustDomain(spiffeId);
        }

        public Instant notBefore() {
            return chain.get(0).getNotBefore().toInstant();
        }

        public Instant notAfter() {
            return chain.get(0).getNotAfter().toInstant();
        }
    }

    /**
     * The trust domain of a SPIFFE ID: {@code example.org} of
     * {@code spiffe://example.org/orders}, in lower case.
     */
    public static String trustDomain(String spiffeId) {
        if (spiffeId == null || !spiffeId.regionMatches(true, 0, "spiffe://", 0, 9)) {
            throw new IllegalArgumentException("a SPIFFE ID begins with spiffe://, not "
                    + spiffeId);
        }
        int slash = spiffeId.indexOf('/', 9);
        String domain = (slash < 0 ? spiffeId.substring(9) : spiffeId.substring(9, slash))
                .toLowerCase(java.util.Locale.ROOT);
        if (domain.isEmpty()) {
            throw new IllegalArgumentException("the SPIFFE ID " + spiffeId + " names no trust "
                    + "domain");
        }
        return domain;
    }

    /** Asks for the workload's X.509-SVID - the first one, when the agent has several. */
    public X509Svid fetchX509Svid() throws IOException {
        if (!PrivateSigningKey.available()) {
            throw new IllegalStateException("an SVID's key off the heap needs OpenSSL 3 on "
                    + "64-bit Linux or CNG on Windows, which are not there");
        }
        SocketChannel channel;
        try {
            channel = SocketChannel.open(UnixDomainSocketAddress.of(socket));
        } catch (java.net.SocketException e) {
            throw new IOException("the Workload API at " + socket + " could not be reached: "
                    + e.getMessage(), e);
        }
        // A Unix socket channel has no read timeout; an agent that never
        // answers gets its connection closed under it instead.
        java.util.concurrent.CompletableFuture<Void> deadline =
                java.util.concurrent.CompletableFuture.runAsync(() -> closeQuietly(channel),
                        java.util.concurrent.CompletableFuture.delayedExecutor(timeoutMillis,
                                java.util.concurrent.TimeUnit.MILLISECONDS));
        try (SecretScope answer = SecretScope.allocate(MAX_ANSWER)) {
            request(channel, "/SpiffeWorkloadAPI/FetchX509SVID", new byte[0]);
            int length = new Reader(channel, answer.segment()).next();
            answer.length(5 + length);
            return parse(answer.segment(), length);
        } catch (java.nio.channels.AsynchronousCloseException timedOut) {
            throw new IOException("the Workload API at " + socket + " did not answer within "
                    + timeoutMillis + " ms", timedOut);
        } finally {
            deadline.cancel(false);
            closeQuietly(channel);
        }
    }

    /**
     * Keeps {@code FetchX509SVID} open and hands every SVID the agent sends to
     * {@code each} - the first right away, then each rotation, each changed
     * bundle - on a thread of its own, until the watch is closed. The SVID's
     * key is {@code each}'s to keep or close.
     *
     * <p>A stream that breaks - the agent restarts, the socket goes - is
     * reported to {@code failed} and opened again, after a second at first and
     * at most half a minute after repeated failures; the first answer of each
     * stream is waited for at most the timeout. Between answers there is no
     * timeout: an agent pushes only when something changed.
     */
    public Watch watchX509Svids(java.util.function.Consumer<X509Svid> each,
            java.util.function.Consumer<IOException> failed) {
        if (!PrivateSigningKey.available()) {
            throw new IllegalStateException("an SVID's key off the heap needs OpenSSL 3 on "
                    + "64-bit Linux or CNG on Windows, which are not there");
        }
        Watch watch = new Watch(each, failed);
        watch.start();
        return watch;
    }

    /** An open {@code FetchX509SVID} stream; closing it ends the stream and its thread. */
    public final class Watch implements AutoCloseable {

        private final java.util.function.Consumer<X509Svid> each;
        private final java.util.function.Consumer<IOException> failed;
        private final Thread thread;
        private volatile SocketChannel channel;
        private volatile boolean closed;
        private volatile int streams;

        private Watch(java.util.function.Consumer<X509Svid> each,
                java.util.function.Consumer<IOException> failed) {
            this.each = each;
            this.failed = failed;
            this.thread = new Thread(this::run, "seclume-spiffe-watch " + socket);
            this.thread.setDaemon(true);
        }

        private void start() {
            thread.start();
        }

        /** How many times the stream was opened - for the tests. */
        public int streams() {
            return streams;
        }

        private void run() {
            long backoff = 1000;
            while (!closed) {
                try {
                    stream();
                    backoff = 1000;
                } catch (IOException e) {
                    if (closed) {
                        return;
                    }
                    failed.accept(e);
                } catch (RuntimeException e) {
                    if (closed) {
                        return;
                    }
                    failed.accept(new IOException("an SVID from the Workload API at " + socket
                            + " could not be taken: " + e.getMessage(), e));
                }
                if (closed) {
                    return;
                }
                try {
                    Thread.sleep(backoff);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                backoff = Math.min(30_000, backoff * 2);
            }
        }

        private void stream() throws IOException {
            SocketChannel opened;
            try {
                opened = SocketChannel.open(UnixDomainSocketAddress.of(socket));
            } catch (java.net.SocketException e) {
                throw new IOException("the Workload API at " + socket + " could not be "
                        + "reached: " + e.getMessage(), e);
            }
            channel = opened;
            streams++;
            if (closed) {
                closeQuietly(opened);
                return;
            }
            java.util.concurrent.CompletableFuture<Void> deadline =
                    java.util.concurrent.CompletableFuture.runAsync(() -> closeQuietly(opened),
                            java.util.concurrent.CompletableFuture.delayedExecutor(
                                    timeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS));
            try (SecretScope answer = SecretScope.allocate(MAX_ANSWER)) {
                request(opened, "/SpiffeWorkloadAPI/FetchX509SVID", new byte[0]);
                Reader reader = new Reader(opened, answer.segment());
                while (!closed) {
                    int length = reader.next();
                    deadline.cancel(false);
                    X509Svid svid = parse(answer.segment(), length);
                    reader.consumed(length);
                    each.accept(svid);
                }
            } catch (java.nio.channels.AsynchronousCloseException stopped) {
                if (!closed) {
                    throw new IOException("the Workload API at " + socket + " did not answer "
                            + "within " + timeoutMillis + " ms", stopped);
                }
            } finally {
                deadline.cancel(false);
                closeQuietly(opened);
            }
        }

        @Override
        public void close() {
            closed = true;
            SocketChannel open = channel;
            if (open != null) {
                closeQuietly(open);
            }
            thread.interrupt();
        }
    }

    private static void closeQuietly(SocketChannel channel) {
        try {
            channel.close();
        } catch (IOException ignored) {
            // closing is all there is to do
        }
    }

    /**
     * A JWT-SVID: whose it is and when it ends - and, in the caller's segment,
     * the token itself, {@code length} bytes of it.
     */
    public record JwtSvid(String spiffeId, Instant expiresAt, int length) {
    }

    /**
     * Asks for a JWT-SVID for {@code audiences} - of {@code spiffeId}, or the
     * workload's first identity when that is {@code null} - and writes the
     * token into {@code target}, from the socket through native memory: a JWT
     * is a bearer credential, and it never becomes a {@code String} here. Its
     * {@code exp} is read where it lies, decoded in native memory.
     */
    public JwtSvid fetchJwtSvid(List<String> audiences, String spiffeId, MemorySegment target)
            throws IOException {
        if (audiences.isEmpty()) {
            throw new IllegalArgumentException("a JWT-SVID is asked for an audience - name at "
                    + "least one");
        }
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        for (String audience : audiences) {
            protobufString(message, 1, audience);
        }
        if (spiffeId != null && !spiffeId.isBlank()) {
            protobufString(message, 2, spiffeId.trim());
        }
        SocketChannel channel;
        try {
            channel = SocketChannel.open(UnixDomainSocketAddress.of(socket));
        } catch (java.net.SocketException e) {
            throw new IOException("the Workload API at " + socket + " could not be reached: "
                    + e.getMessage(), e);
        }
        java.util.concurrent.CompletableFuture<Void> deadline =
                java.util.concurrent.CompletableFuture.runAsync(() -> closeQuietly(channel),
                        java.util.concurrent.CompletableFuture.delayedExecutor(timeoutMillis,
                                java.util.concurrent.TimeUnit.MILLISECONDS));
        try (SecretScope answer = SecretScope.allocate(MAX_ANSWER)) {
            request(channel, "/SpiffeWorkloadAPI/FetchJWTSVID", message.toByteArray());
            int length = new Reader(channel, answer.segment()).next();
            answer.length(5 + length);
            return jwt(answer.segment(), length, target);
        } catch (java.nio.channels.AsynchronousCloseException timedOut) {
            throw new IOException("the Workload API at " + socket + " did not answer within "
                    + timeoutMillis + " ms", timedOut);
        } finally {
            deadline.cancel(false);
            closeQuietly(channel);
        }
    }

    private static void protobufString(ByteArrayOutputStream out, int field, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8); // seclume-allow: an audience or a SPIFFE ID - public
        out.write((field << 3) | 2);
        int length = bytes.length;
        while ((length & ~0x7f) != 0) {
            out.write((length & 0x7f) | 0x80);
            length >>>= 7;
        }
        out.write(length);
        out.write(bytes, 0, bytes.length);
    }

    /** {@code JWTSVIDResponse}: the first SVID's token into {@code target}, its ID and end. */
    static JwtSvid jwt(MemorySegment answer, int length, MemorySegment target)
            throws IOException {
        Protobuf response = new Protobuf(answer, 5, 5 + length);
        long[] svid = null;
        while (response.next()) {
            if (response.field() == 1 && response.wire() == 2) {
                svid = response.bytes();
                break;
            }
            response.skip();
        }
        if (svid == null) {
            throw new IOException("the Workload API's answer holds no JWT-SVID");
        }
        String id = null;
        long[] where = null;
        Protobuf fields = new Protobuf(answer, svid[0], svid[0] + svid[1]);
        while (fields.next()) {
            if (fields.wire() != 2) {
                fields.skip();
                continue;
            }
            long[] value = fields.bytes();
            if (fields.field() == 1) {
                // seclume-allow: the SPIFFE ID, which the token names openly
                id = new String(publicBytes(answer, value), StandardCharsets.UTF_8);
            } else if (fields.field() == 2) {
                where = value;
            }
        }
        if (id == null || where == null || where[1] == 0) {
            throw new IOException("the Workload API's JWT-SVID lacks its ID or token");
        }
        if (where[1] > target.byteSize()) {
            throw new IOException("the JWT-SVID is " + where[1] + " bytes, more than the "
                    + target.byteSize() + " there is room for");
        }
        MemorySegment.copy(answer, where[0], target, 0, where[1]);
        return new JwtSvid(id, expiry(target, (int) where[1]), (int) where[1]);
    }

    /** The {@code exp} of a JWT in native memory, its payload decoded there. */
    private static Instant expiry(MemorySegment jwt, int length) throws IOException {
        int first = -1;
        int second = -1;
        for (int i = 0; i < length; i++) {
            if (jwt.get(ValueLayout.JAVA_BYTE, i) == '.') {
                if (first < 0) {
                    first = i;
                } else {
                    second = i;
                    break;
                }
            }
        }
        if (first < 0 || second < 0) {
            throw new IOException("the JWT-SVID is no JWT: not three parts");
        }
        int encoded = second - first - 1;
        try (SecretScope payload = SecretScope.allocate(encoded + 4);
             SecretScope decoded = SecretScope.allocate(
                     space.seclume.internal.Base64Off.decodedUpperBound(encoded + 4))) {
            // base64url to base64, in native memory
            for (int i = 0; i < encoded; i++) {
                byte c = jwt.get(ValueLayout.JAVA_BYTE, first + 1 + i);
                payload.segment().set(ValueLayout.JAVA_BYTE, i,
                        c == '-' ? (byte) '+' : c == '_' ? (byte) '/' : c);
            }
            int n = space.seclume.internal.Base64Off.decode(payload.segment(), 0, encoded,
                    decoded.segment(), 0);
            if (!space.seclume.internal.JsonOff.has(decoded.segment(), n, "exp")) {
                return null;
            }
            return Instant.ofEpochSecond(space.seclume.internal.JsonOff.number(
                    decoded.segment(), n, "exp"));
        } catch (RuntimeException e) {
            throw new IOException("the JWT-SVID's claims could not be read: " + e.getMessage(),
                    e);
        }
    }

    private static void request(SocketChannel channel, String path, byte[] message)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(PREFACE, 0, PREFACE.length);
        // SETTINGS: no push, a window large enough for any SVID.
        byte[] settings = {0, 2, 0, 0, 0, 0, 0, 4, (byte) (WINDOW >>> 24),
            (byte) (WINDOW >>> 16), (byte) (WINDOW >>> 8), (byte) WINDOW};
        frame(out, SETTINGS, 0, 0, settings);
        frame(out, WINDOW_UPDATE, 0, 0, int32(WINDOW - 65535));
        ByteArrayOutputStream block = new ByteArrayOutputStream();
        literal(block, ":method", "POST");
        literal(block, ":scheme", "http");
        literal(block, ":path", path);
        literal(block, ":authority", "localhost");
        literal(block, "content-type", "application/grpc");
        literal(block, "te", "trailers");
        literal(block, "workload.spiffe.io", "true");
        frame(out, HEADERS, END_HEADERS, 1, block.toByteArray());
        // One gRPC message: no compression, its length, the request.
        byte[] grpc = new byte[5 + message.length];
        System.arraycopy(int32(message.length), 0, grpc, 1, 4);
        System.arraycopy(message, 0, grpc, 5, message.length);
        frame(out, DATA, END_STREAM, 1, grpc);
        write(channel, out.toByteArray());
    }

    /** A header field as a literal without indexing, with a literal name - nothing left in a table. */
    private static void literal(ByteArrayOutputStream block, String name, String value) {
        block.write(0x00);
        string(block, name);
        string(block, value);
    }

    private static void string(ByteArrayOutputStream block, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII); // seclume-allow: a header of the request - no secret
        if (bytes.length >= 127) {
            throw new IllegalArgumentException("a header longer than this client writes");
        }
        block.write(bytes.length);
        block.write(bytes, 0, bytes.length);
    }

    private static byte[] int32(int value) {
        return new byte[] {(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8),
            (byte) value};
    }

    private static void frame(ByteArrayOutputStream out, int type, int flags, int stream,
            byte[] payload) {
        out.write(payload.length >>> 16);
        out.write(payload.length >>> 8);
        out.write(payload.length);
        out.write(type);
        out.write(flags);
        byte[] id = int32(stream);
        out.write(id, 0, 4);
        out.write(payload, 0, payload.length);
    }

    private static void write(SocketChannel channel, byte[] bytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }

    /**
     * The response messages of stream 1, one after the other, each read from
     * the socket straight into {@code into} - native memory - with nothing on
     * the way. A frame may end one message and begin the next; what is read
     * past a message is kept for the next one.
     */
    private static final class Reader {

        private final SocketChannel channel;
        private final MemorySegment into;
        private long filled;
        private long unacknowledged;
        private int messages;

        Reader(SocketChannel channel, MemorySegment into) {
            this.channel = channel;
            this.into = into;
        }

        /** The next whole message: its protobuf's length; it starts at offset 5. */
        int next() throws IOException {
            byte[] head = new byte[9];
            while (true) {
                if (filled >= 5) {
                    long message = Integer.toUnsignedLong(
                            into.get(ValueLayout.JAVA_INT_UNALIGNED.withOrder(
                                    java.nio.ByteOrder.BIG_ENDIAN), 1));
                    if (into.get(ValueLayout.JAVA_BYTE, 0) != 0) {
                        throw new IOException("the Workload API answered compressed, which "
                                + "was not asked for");
                    }
                    if (message > into.byteSize() - 5) {
                        throw new IOException("the Workload API's answer is larger than an "
                                + "SVID can be");
                    }
                    if (filled >= 5 + message) {
                        messages++;
                        return (int) message;
                    }
                }
                readFully(channel, ByteBuffer.wrap(head));
                int length = ((head[0] & 0xff) << 16) | ((head[1] & 0xff) << 8)
                        | (head[2] & 0xff);
                int type = head[3] & 0xff;
                int flags = head[4] & 0xff;
                int stream = ((head[5] & 0x7f) << 24) | ((head[6] & 0xff) << 16)
                        | ((head[7] & 0xff) << 8) | (head[8] & 0xff);
                if (type == DATA && stream == 1) {
                    int padding = 0;
                    int body = length;
                    if ((flags & PADDED) != 0) {
                        byte[] pad = new byte[1];
                        readFully(channel, ByteBuffer.wrap(pad));
                        padding = pad[0] & 0xff;
                        body = length - 1 - padding;
                    }
                    if (body < 0 || filled + body > into.byteSize()) {
                        throw new IOException("the Workload API's answer is larger than an "
                                + "SVID can be");
                    }
                    readFully(channel, into.asSlice(filled, body).asByteBuffer());
                    filled += body;
                    skip(channel, padding);
                    // The whole frame counts against the window, padding included.
                    unacknowledged += length;
                    if ((flags & END_STREAM) != 0 && filled < 5) {
                        throw new IOException(messages == 0
                                ? "the Workload API ended its answer half-way"
                                : "the Workload API ended the stream");
                    }
                    continue;
                }
                byte[] payload = new byte[length];
                readFully(channel, ByteBuffer.wrap(payload));
                switch (type) {
                    case SETTINGS -> {
                        if ((flags & ACK) == 0) {
                            ByteArrayOutputStream ack = new ByteArrayOutputStream();
                            frame(ack, SETTINGS, ACK, 0, new byte[0]);
                            courtesy(channel, ack.toByteArray());
                        }
                    }
                    case PING -> {
                        if ((flags & ACK) == 0) {
                            ByteArrayOutputStream pong = new ByteArrayOutputStream();
                            frame(pong, PING, ACK, 0, payload);
                            courtesy(channel, pong.toByteArray());
                        }
                    }
                    case HEADERS -> {
                        if (stream == 1 && (flags & END_STREAM) != 0) {
                            // Trailers before a message: the call failed. SPIRE
                            // answers an unregistered workload this way. After
                            // one, the agent ended the stream.
                            throw new IOException(messages == 0 ? "the Workload API gave no "
                                    + "SVID - is this workload registered for one?"
                                    : "the Workload API ended the stream");
                        }
                    }
                    case RST_STREAM -> throw new IOException("the Workload API reset the call "
                            + "(HTTP/2 error " + (payload.length >= 4
                                    ? ((payload[0] & 0xff) << 24 | (payload[1] & 0xff) << 16
                                    | (payload[2] & 0xff) << 8 | (payload[3] & 0xff)) : -1)
                            + ")");
                    case GOAWAY -> throw new IOException("the Workload API closed the "
                            + "connection");
                    default -> {
                        // WINDOW_UPDATE, PRIORITY, an unknown type: nothing to do
                    }
                }
            }
        }

        /**
         * Done with the message at the front: what was read past it moves up,
         * the bytes it leaves behind are zeroed, and the flow-control window
         * opens again by what was read - so that a stream lives longer than its
         * first megabyte.
         */
        void consumed(int message) throws IOException {
            long used = 5L + message;
            long rest = filled - used;
            if (rest > 0) {
                MemorySegment.copy(into, used, into, 0, rest);
            }
            into.asSlice(Math.max(0, rest), used).fill((byte) 0);
            filled = Math.max(0, rest);
            if (unacknowledged > 0) {
                ByteArrayOutputStream update = new ByteArrayOutputStream();
                frame(update, WINDOW_UPDATE, 0, 0, int32((int) unacknowledged));
                frame(update, WINDOW_UPDATE, 0, 1, int32((int) unacknowledged));
                write(channel, update.toByteArray());
                unacknowledged = 0;
            }
        }
    }

    /**
     * An acknowledgement the protocol asks for. Owed, not needed: a server
     * that has already said its last word and gone - an unregistered
     * workload's trailers - is read to the end rather than written to.
     */
    private static void courtesy(SocketChannel channel, byte[] frame) {
        try {
            write(channel, frame);
        } catch (IOException gone) {
            // what it said is still to be read
        }
    }

    private static void readFully(SocketChannel channel, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) {
                throw new IOException("the Workload API closed the connection before its answer "
                        + "was complete");
            }
        }
    }

    private static void skip(SocketChannel channel, int bytes) throws IOException {
        if (bytes > 0) {
            readFully(channel, ByteBuffer.allocateDirect(bytes));
        }
    }

    /**
     * Walks {@code X509SVIDResponse} where it lies: the first {@code svids}
     * entry's ID, certificates and bundle become objects, its key goes to the
     * key store of the platform from native memory.
     */
    static X509Svid parse(MemorySegment answer, int length) throws IOException {
        Protobuf response = new Protobuf(answer, 5, 5 + length);
        long[] svid = null;
        Map<String, List<X509Certificate>> federated = new java.util.LinkedHashMap<>();
        while (response.next()) {
            if (response.field() == 1 && response.wire() == 2 && svid == null) {
                svid = response.bytes();
            } else if (response.field() == 3 && response.wire() == 2) {
                // federated_bundles, a map: entries of key (1) and value (2)
                long[] entry = response.bytes();
                Protobuf pair = new Protobuf(answer, entry[0], entry[0] + entry[1]);
                String domain = null;
                byte[] certificates = null; // seclume-allow: a trust bundle, which is public
                while (pair.next()) {
                    if (pair.wire() != 2) {
                        pair.skip();
                    } else if (pair.field() == 1) {
                        // seclume-allow: a trust domain's name, which is public
                        domain = new String(publicBytes(answer, pair.bytes()),
                                StandardCharsets.UTF_8);
                    } else if (pair.field() == 2) {
                        certificates = publicBytes(answer, pair.bytes());
                    } else {
                        pair.skip();
                    }
                }
                if (domain != null && certificates != null && certificates.length > 0) {
                    federated.put(trustDomain(domain.startsWith("spiffe://") ? domain
                            : "spiffe://" + domain), certificates(certificates));
                }
            } else {
                response.skip();
            }
        }
        if (svid == null) {
            throw new IOException("the Workload API's answer holds no X.509-SVID");
        }
        String id = null;
        byte[] chain = null; // seclume-allow: the certificates, which are public
        byte[] bundle = null; // seclume-allow: the trust bundle, which is public
        long[] key = null;
        Protobuf fields = new Protobuf(answer, svid[0], svid[0] + svid[1]);
        while (fields.next()) {
            if (fields.wire() != 2) {
                fields.skip();
                continue;
            }
            long[] value = fields.bytes();
            switch (fields.field()) {
                // seclume-allow: the SPIFFE ID, which every certificate carries
                case 1 -> id = new String(publicBytes(answer, value), StandardCharsets.UTF_8);
                case 2 -> chain = publicBytes(answer, value);
                case 3 -> key = value;
                case 4 -> bundle = publicBytes(answer, value);
                default -> {
                    // the hint, and what a later version adds
                }
            }
        }
        if (id == null || chain == null || key == null) {
            throw new IOException("the Workload API's X.509-SVID lacks its ID, certificate or "
                    + "key");
        }
        List<X509Certificate> certificates = certificates(chain);
        PrivateSigningKey signing;
        try {
            signing = PrivateSigningKey.decode(answer.asSlice(key[0], key[1]), (int) key[1]);
        } catch (IllegalArgumentException unreadable) {
            // The agent's answer, not the caller's setting: a broken answer.
            throw new IOException("the Workload API's X.509-SVID key could not be read",
                    unreadable);
        }
        try {
            if (!Arrays.equals(signing.publicKey(), certificates.get(0).getPublicKey()
                    .getEncoded())) {
                throw new IOException("the Workload API's key is not its certificate's");
            }
            return new X509Svid(id, certificates, bundle == null ? List.of()
                    : certificates(bundle), signing, federated);
        } catch (IOException | RuntimeException e) {
            signing.close();
            throw e;
        }
    }

    private static byte[] publicBytes(MemorySegment answer, long[] value) {
        return answer.asSlice(value[0], value[1]).toArray(ValueLayout.JAVA_BYTE);
    }

    private static List<X509Certificate> certificates(byte[] der) throws IOException {
        try {
            Collection<? extends Certificate> read = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(der));
            if (read.isEmpty()) {
                throw new IOException("an SVID without a certificate");
            }
            return read.stream().map(X509Certificate.class::cast).toList();
        } catch (GeneralSecurityException e) {
            throw new IOException("the SVID's certificates could not be read", e);
        }
    }

    /** A protobuf message read in place: field by field, nothing copied. */
    static final class Protobuf {

        private final MemorySegment data;
        private long at;
        private final long end;
        private int field;
        private int wire;

        Protobuf(MemorySegment data, long from, long end) {
            this.data = data;
            this.at = from;
            this.end = end;
        }

        boolean next() throws IOException {
            if (at >= end) {
                return false;
            }
            long tag = varint();
            field = (int) (tag >>> 3);
            wire = (int) (tag & 7);
            return true;
        }

        int field() {
            return field;
        }

        int wire() {
            return wire;
        }

        /** A length-delimited value: where it starts and how long it is. */
        long[] bytes() throws IOException {
            long length = varint();
            if (length < 0 || at + length > end) {
                throw new IOException("the Workload API's answer is cut short");
            }
            long[] value = {at, length};
            at += length;
            return value;
        }

        void skip() throws IOException {
            switch (wire) {
                case 0 -> varint();
                case 1 -> at += 8;
                case 2 -> bytes();
                case 5 -> at += 4;
                default -> throw new IOException("the Workload API's answer is no protobuf "
                        + "this reads (wire type " + wire + ")");
            }
            if (at > end) {
                throw new IOException("the Workload API's answer is cut short");
            }
        }

        private long varint() throws IOException {
            long value = 0;
            for (int shift = 0; shift < 64; shift += 7) {
                if (at >= end) {
                    throw new IOException("the Workload API's answer is cut short");
                }
                int b = data.get(ValueLayout.JAVA_BYTE, at++) & 0xff;
                value |= (long) (b & 0x7f) << shift;
                if ((b & 0x80) == 0) {
                    return value;
                }
            }
            throw new IOException("the Workload API's answer has a varint too long");
        }
    }
}
