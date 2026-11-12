package space.seclume.nats;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Arrays;
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

    private volatile boolean handshakeDone;
    private byte[] handshakeLine = new byte[512];
    private int handshakeLen;

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
        this.transport = new SocketStreamTransport(this.socket, this.in, this.out);
        this.closed = false;
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
            if (handshakeLen >= MAX_HANDSHAKE_BYTES) {
                throw new IOException("a NATS handshake line longer than "
                        + MAX_HANDSHAKE_BYTES + " bytes");
            }
            if (handshakeLen == handshakeLine.length) {
                handshakeLine = Arrays.copyOf(handshakeLine, handshakeLine.length * 2);
            }
            handshakeLine[handshakeLen++] = b;
            if (b == '\n') {
                byte[] line = Arrays.copyOf(handshakeLine, handshakeLen);
                handshakeLen = 0;
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
        int at = ConnectLine.credentialSlot(line, settings.mode, SeclumeNats.PLACEHOLDER);
        if (at < 0) {
            throw new IOException("the NATS client's CONNECT has no " + (settings.mode
                    == NatsSettings.AuthMode.TOKEN ? "\"auth_token\"" : "\"pass\"")
                    + " that is the placeholder - it was given a password or token of its own, "
                    + "which is on the heap already and is not sent. Leave credentials to the "
                    + "seclume URL");
        }
        String mechanism = settings.mode == NatsSettings.AuthMode.PASSWORD ? "password" : "token";
        Observed.secretUse("nats", settings.target(), mechanism);
        try (SecretScope secret = SecretScope.fromProvider(settings.secret)) {
            MemorySegment seg = secret.segment();
            int rawLen = secret.length();
            int escapedLen = ConnectLine.jsonEscapedLength(seg, rawLen);
            int afterOffset = at + PLACEHOLDER_BYTES.length;
            int afterLen = line.length - afterOffset;
            int total = at + escapedLen + afterLen;
            try (SecretScope outScope = SecretScope.allocate(total)) {
                MemorySegment out = outScope.segment();
                MemorySegment.copy(line, 0, out, JAVA_BYTE, 0, at);
                int pos = ConnectLine.writeJsonEscaped(seg, rawLen, out, at);
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
}
