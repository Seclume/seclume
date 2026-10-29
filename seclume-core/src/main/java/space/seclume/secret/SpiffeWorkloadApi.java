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
 * the first response message is whole. {@code FetchX509SVID} is a stream; a
 * call takes its first message and closes - asked again before the SVID
 * reaches the point SPIRE rotates it, it brings the new one.
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
            List<X509Certificate> bundle, PrivateSigningKey key) {

        public X509Svid {
            chain = List.copyOf(chain);
            bundle = List.copyOf(bundle);
        }

        public Instant notBefore() {
            return chain.get(0).getNotBefore().toInstant();
        }

        public Instant notAfter() {
            return chain.get(0).getNotAfter().toInstant();
        }
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
            request(channel);
            int length = response(channel, answer.segment());
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

    private static void closeQuietly(SocketChannel channel) {
        try {
            channel.close();
        } catch (IOException ignored) {
            // closing is all there is to do
        }
    }

    private static void request(SocketChannel channel) throws IOException {
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
        literal(block, ":path", "/SpiffeWorkloadAPI/FetchX509SVID");
        literal(block, ":authority", "localhost");
        literal(block, "content-type", "application/grpc");
        literal(block, "te", "trailers");
        literal(block, "workload.spiffe.io", "true");
        frame(out, HEADERS, END_HEADERS, 1, block.toByteArray());
        // One gRPC message, the empty X509SVIDRequest: no compression, length 0.
        frame(out, DATA, END_STREAM, 1, new byte[5]);
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
     * Reads frames until stream 1 has delivered one whole gRPC message; the
     * message - and only it - goes into {@code into}, native memory, straight
     * from the socket. Returns the protobuf's length; it starts at offset 5.
     */
    private static int response(SocketChannel channel, MemorySegment into) throws IOException {
        byte[] head = new byte[9];
        long filled = 0;
        while (true) {
            readFully(channel, ByteBuffer.wrap(head));
            int length = ((head[0] & 0xff) << 16) | ((head[1] & 0xff) << 8) | (head[2] & 0xff);
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
                    throw new IOException("the Workload API's answer is larger than an SVID "
                            + "can be");
                }
                readFully(channel, into.asSlice(filled, body).asByteBuffer());
                filled += body;
                skip(channel, padding);
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
                        return (int) message;
                    }
                }
                if ((flags & END_STREAM) != 0) {
                    throw new IOException("the Workload API ended its answer half-way");
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
                        // answers an unregistered workload this way.
                        throw new IOException("the Workload API gave no SVID - is this "
                                + "workload registered for one?");
                    }
                }
                case RST_STREAM -> throw new IOException("the Workload API reset the call "
                        + "(HTTP/2 error " + (payload.length >= 4
                                ? ((payload[0] & 0xff) << 24 | (payload[1] & 0xff) << 16
                                | (payload[2] & 0xff) << 8 | (payload[3] & 0xff)) : -1) + ")");
                case GOAWAY -> throw new IOException("the Workload API closed the connection");
                default -> {
                    // WINDOW_UPDATE, PRIORITY, an unknown type: nothing to do
                }
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
        while (response.next()) {
            if (response.field() == 1 && response.wire() == 2) {
                svid = response.bytes();
                break;
            }
            response.skip();
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
        PrivateSigningKey signing = PrivateSigningKey.decode(answer.asSlice(key[0], key[1]),
                (int) key[1]);
        try {
            if (!Arrays.equals(signing.publicKey(), certificates.get(0).getPublicKey()
                    .getEncoded())) {
                throw new IOException("the Workload API's key is not its certificate's");
            }
            return new X509Svid(id, certificates, bundle == null ? List.of()
                    : certificates(bundle), signing);
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
