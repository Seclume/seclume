package space.seclume.nats;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Map;
import java.util.WeakHashMap;

import io.nats.client.Options;
import io.nats.client.impl.SocketDataPort;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.Transport;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.jfr.Observed;
import space.seclume.secret.SecretScope;

/**
 * A NATS {@link io.nats.client.impl.DataPort} (extending {@link SocketDataPort})
 * backed by seclume's {@link TlsLayer}.
 *
 * <p>When the connection is configured for a password or token login, the
 * client is given {@link SeclumeNats#PLACEHOLDER}. This port intercepts the
 * initial {@code CONNECT {...}\r\n} command line on {@link #write(byte[], int)},
 * verifies that the client did not set a password or token of its own, and
 * replaces the placeholder in native memory with the JSON-escaped secret from
 * the {@link space.seclume.secret.SecretProvider} before handing the buffer to
 * seclume's TLS 1.3 cipher. Everything after that first line is passed through
 * unchanged.
 */
public final class SeclumeNatsDataPort extends SocketDataPort {

    private static final int MAX_HANDSHAKE_BYTES = 64 * 1024;
    private static final byte[] CONNECT_PREFIX =
            "CONNECT {".getBytes(StandardCharsets.US_ASCII); // seclume-allow: protocol prefix - public
    private static final byte[] PLACEHOLDER_BYTES =
            SeclumeNats.PLACEHOLDER.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the placeholder - not a secret

    private static final Map<Options, NatsSettings> REGISTRY = new WeakHashMap<>();

    static void register(Options options, NatsSettings settings) {
        synchronized (REGISTRY) {
            REGISTRY.put(options, settings);
        }
    }

    private Options options;
    private NatsSettings settings;
    private volatile Transport transport;
    private volatile TlsLayer tls;
    private volatile boolean closed;

    private boolean handshakeDone;
    private final ByteArrayOutputStream handshakeBuffer = new ByteArrayOutputStream();

    /** Instantiated reflectively by {@link Options#buildDataPort()}. */
    public SeclumeNatsDataPort() {
    }

    @Override
    public void afterConstruct(Options options) {
        this.options = options;
        synchronized (REGISTRY) {
            this.settings = REGISTRY.get(options);
        }
        if (this.settings != null
                && this.settings.mode != NatsSettings.AuthMode.PASSWORD
                && this.settings.mode != NatsSettings.AuthMode.TOKEN) {
            this.handshakeDone = true;
        }
    }

    private void ensureOpened() throws IOException {
        if (this.transport != null) {
            return;
        }
        if (this.socket == null || this.in == null || this.out == null) {
            throw new IOException("NATS socket was not opened");
        }
        this.transport = new PlainSocketTransport(this.socket, this.in, this.out);
        this.closed = false;
        this.handshakeBuffer.reset();
        this.handshakeDone = settings == null
                || (settings.mode != NatsSettings.AuthMode.PASSWORD
                    && settings.mode != NatsSettings.AuthMode.TOKEN);
    }

    @Override
    public void upgradeToSecure() throws IOException {
        if (tls != null) {
            return;
        }
        ensureOpened();
        Transport plain = this.transport;
        String peerHost = settings != null ? settings.host : this.host;
        TrustChoice.Choice trust = settings != null ? settings.trust : null;
        try {
            this.tls = TrustChoice.using(trust, () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, plain, peerHost, this.port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
            this.isSecure = true;
        } catch (SQLException e) {
            throw e.getCause() instanceof IOException io ? io : new IOException(e.getMessage(), e);
        }
    }

    @Override
    public int read(byte[] dst, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        }
        ensureOpened();
        Transport t = this.transport;
        if (closed || t == null) {
            throw new IOException("the NATS data port is closed");
        }
        TlsLayer layer = this.tls;
        try {
            ByteBuffer into = ByteBuffer.wrap(dst, off, len);
            return layer != null ? layer.read(into) : t.read(into);
        } catch (IOException e) {
            if (!t.isOpen() && !closed) {
                throw new SocketTimeoutException("no answer from NATS at " + host + ":" + port);
            }
            throw e;
        }
    }

    @Override
    public synchronized void write(byte[] src, int toWrite) throws IOException {
        if (toWrite <= 0) {
            return;
        }
        ensureOpened();
        if (handshakeDone) {
            sendRaw(ByteBuffer.wrap(src, 0, toWrite));
            return;
        }
        int at = 0;
        while (at < toWrite && !handshakeDone) {
            byte b = src[at++];
            handshakeBuffer.write(b);
            if (handshakeBuffer.size() > MAX_HANDSHAKE_BYTES) {
                throw new IOException("a NATS handshake line longer than "
                        + MAX_HANDSHAKE_BYTES + " bytes");
            }
            if (b == '\n') {
                byte[] line = handshakeBuffer.toByteArray();
                handshakeBuffer.reset();
                if (startsWithConnect(line)) {
                    rewriteAndSendConnect(line);
                    handshakeDone = true;
                } else {
                    sendRaw(ByteBuffer.wrap(line));
                }
            }
        }
        if (at < toWrite) {
            sendRaw(ByteBuffer.wrap(src, at, toWrite - at));
        }
    }

    private void rewriteAndSendConnect(byte[] line) throws IOException {
        if (settings.tls && tls == null) {
            throw new IOException("refusing to send NATS credential before TLS is active");
        }
        if (options != null) {
            verifyPlaceholderUnchanged();
        }
        int at = indexOf(line, PLACEHOLDER_BYTES);
        if (at < 0) {
            throw new IOException("the NATS client was given a password or token of its own; "
                    + "that secret is on the heap already and is not sent. Leave credentials "
                    + "to the seclume URL");
        }
        String mechanism = settings.mode == NatsSettings.AuthMode.PASSWORD ? "password" : "token";
        Observed.secretUse("nats", settings.target(), mechanism);
        try (SecretScope secret = SecretScope.fromProvider(settings.secret)) {
            MemorySegment seg = secret.segment();
            int rawLen = secret.length();
            int escapedLen = jsonEscapedLength(seg, rawLen);
            int afterOffset = at + PLACEHOLDER_BYTES.length;
            int afterLen = line.length - afterOffset;
            int total = at + escapedLen + afterLen;
            try (SecretScope outScope = SecretScope.allocate(total)) {
                MemorySegment out = outScope.segment();
                MemorySegment.copy(line, 0, out, JAVA_BYTE, 0, at);
                int pos = writeJsonEscaped(seg, rawLen, out, at);
                MemorySegment.copy(line, afterOffset, out, JAVA_BYTE, pos, afterLen);
                pos += afterLen;
                outScope.length(pos);
                sendRaw(out.asSlice(0, pos).asByteBuffer());
            }
        }
    }

    private void verifyPlaceholderUnchanged() throws IOException {
        if (settings.mode == NatsSettings.AuthMode.PASSWORD) {
            if (!matchesPlaceholder(options.getPasswordChars())) {
                throw new IOException("the NATS client was given a password of its own; "
                        + "that password is on the heap already and is not sent");
            }
        } else if (settings.mode == NatsSettings.AuthMode.TOKEN) {
            if (!matchesPlaceholder(options.getTokenChars())) {
                throw new IOException("the NATS client was given a token of its own; "
                        + "that token is on the heap already and is not sent");
            }
        }
    }

    private static boolean matchesPlaceholder(char[] actual) { // seclume-allow: checks that the placeholder was not replaced by a heap secret
        if (actual == null || actual.length != SeclumeNats.PLACEHOLDER.length()) {
            return false;
        }
        for (int i = 0; i < actual.length; i++) {
            if (actual[i] != SeclumeNats.PLACEHOLDER.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Computes the JSON-escaped UTF-8 byte length of {@code secret} in native
     * memory without creating any heap objects.
     */
    static int jsonEscapedLength(MemorySegment secret, int length) {
        int total = 0;
        for (int i = 0; i < length; i++) {
            int b = secret.get(JAVA_BYTE, i) & 0xff;
            if (b == '"' || b == '\\' || b == '/' || b == '\b' || b == '\f'
                    || b == '\n' || b == '\r' || b == '\t') {
                total += 2;
            } else if (b < 0x20) {
                total += 6;
            } else {
                total += 1;
            }
        }
        return total;
    }

    /** Writes the JSON-escaped bytes of {@code secret} into {@code out} at {@code offset}. */
    static int writeJsonEscaped(MemorySegment secret, int length,
                                MemorySegment out, int offset) {
        int p = offset;
        for (int i = 0; i < length; i++) {
            int b = secret.get(JAVA_BYTE, i) & 0xff;
            switch (b) {
                case '"' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) '"');
                }
                case '\\' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                }
                case '/' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) '/');
                }
                case '\b' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 'b');
                }
                case '\f' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 'f');
                }
                case '\n' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 'n');
                }
                case '\r' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 'r');
                }
                case '\t' -> {
                    out.set(JAVA_BYTE, p++, (byte) '\\');
                    out.set(JAVA_BYTE, p++, (byte) 't');
                }
                default -> {
                    if (b < 0x20) {
                        out.set(JAVA_BYTE, p++, (byte) '\\');
                        out.set(JAVA_BYTE, p++, (byte) 'u');
                        out.set(JAVA_BYTE, p++, (byte) '0');
                        out.set(JAVA_BYTE, p++, (byte) '0');
                        out.set(JAVA_BYTE, p++, hexDigit((b >>> 4) & 0x0f));
                        out.set(JAVA_BYTE, p++, hexDigit(b & 0x0f));
                    } else {
                        out.set(JAVA_BYTE, p++, (byte) b);
                    }
                }
            }
        }
        return p;
    }

    private static byte hexDigit(int nibble) {
        return (byte) (nibble < 10 ? ('0' + nibble) : ('a' + (nibble - 10)));
    }

    private static boolean startsWithConnect(byte[] line) {
        if (line.length < CONNECT_PREFIX.length) {
            return false;
        }
        for (int i = 0; i < CONNECT_PREFIX.length; i++) {
            if (line[i] != CONNECT_PREFIX[i]) {
                return false;
            }
        }
        return true;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private void sendRaw(ByteBuffer bytes) throws IOException {
        Transport t = this.transport;
        if (closed || t == null) {
            throw new IOException("the NATS data port is closed");
        }
        TlsLayer layer = this.tls;
        if (layer != null) {
            layer.write(bytes);
        } else {
            while (bytes.hasRemaining()) {
                t.write(bytes);
            }
        }
    }

    @Override
    public void shutdownInput() throws IOException {
        if (!isSecure && socket != null) {
            socket.shutdownInput();
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        TlsLayer layer = this.tls;
        if (layer != null) {
            try {
                layer.close();
            } catch (Exception ignored) {
                // closing transport next
            }
        }
        Transport t = this.transport;
        if (t != null) {
            t.close();
        }
        Socket s = this.socket;
        if (s != null && !s.isClosed()) {
            s.close();
        }
    }

    @Override
    public void flush() {
        // Every write goes directly to the socket or TLS record layer.
    }

    private static final class PlainSocketTransport implements Transport {

        private final Socket socket;
        private final InputStream in;
        private final OutputStream out;

        PlainSocketTransport(Socket socket, InputStream in, OutputStream out) {
            this.socket = socket;
            this.in = in;
            this.out = out;
        }

        @Override
        public int read(ByteBuffer into) throws IOException {
            int rem = into.remaining();
            if (rem == 0) {
                return 0;
            }
            if (into.hasArray()) {
                int n = in.read(into.array(), into.arrayOffset() + into.position(), rem);
                if (n > 0) {
                    into.position(into.position() + n);
                }
                return n;
            }
            byte[] buf = new byte[Math.min(rem, 16 * 1024)];
            int n = in.read(buf, 0, buf.length);
            if (n > 0) {
                into.put(buf, 0, n);
            }
            return n;
        }

        @Override
        public int write(ByteBuffer from) throws IOException {
            int rem = from.remaining();
            if (rem == 0) {
                return 0;
            }
            if (from.hasArray()) {
                out.write(from.array(), from.arrayOffset() + from.position(), rem);
                out.flush();
                from.position(from.limit());
                return rem;
            }
            byte[] buf = new byte[rem];
            from.get(buf);
            out.write(buf);
            out.flush();
            return rem;
        }

        @Override
        public boolean isOpen() {
            return !socket.isClosed();
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
                // On close an error has no consequences.
            }
        }
    }
}
