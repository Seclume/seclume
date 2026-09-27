package space.seclume.rabbitmq;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Arrays;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretScope;

/**
 * The socket the RabbitMQ client gets: connected and encrypted with seclume's
 * own TLS 1.3 when the client asks it to connect, and a pipe after that -
 * except for one frame.
 *
 * <p>The client logs in with SASL PLAIN in {@code Connection.Start-Ok}, the
 * second thing it sends. It was given a placeholder for the password, so the
 * response it builds is {@code \0user\0placeholder}. This socket takes that
 * frame apart and writes it again with the real response - {@code
 * \0user\0password}, from the secret provider, in native memory - and with the
 * lengths that follow from it, which are written there as well: a length is a
 * fact about the password. Everything else, before and after, goes through as
 * the client wrote it.
 *
 * <p>A response that is not the placeholder is refused rather than sent: the
 * application set a password on the client, and that one is a String already.
 */
final class AmqpSocket extends Socket {

    private static final byte FRAME_METHOD = 1;
    private static final byte FRAME_END = (byte) 0xCE;
    private static final int MAX_HANDSHAKE_FRAME = 128 * 1024;

    private final RabbitSettings settings;
    private final Object writing = new Object();
    private volatile SocketTransport transport;
    private volatile TlsLayer tls;
    private volatile boolean closed;
    private int timeout;

    // the handshake, before Start-Ok has gone
    private boolean rewritten;
    private int headerLeft = 8;                        // "AMQP" 0 0 9 1
    private final java.io.ByteArrayOutputStream frame = new java.io.ByteArrayOutputStream();

    AmqpSocket(RabbitSettings settings) {
        this.settings = settings;
    }

    @Override
    public void connect(SocketAddress ignored, int connectTimeout) throws IOException {
        if (transport != null) {
            throw new SocketException("already connected");
        }
        SocketTransport opened = SocketTransport.connect(settings.host, settings.port,
                connectTimeout > 0 ? connectTimeout : settings.connectTimeout);
        try {
            opened.networkTimeout(timeout > 0 ? timeout : settings.timeout);
            tls = TrustChoice.using(settings.trust, () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, opened, settings.host,
                            settings.port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
            transport = opened;
        } catch (SQLException e) {
            opened.close();
            throw e.getCause() instanceof IOException io ? io : new IOException(e.getMessage(), e);
        } catch (IOException | RuntimeException e) {
            opened.close();
            throw e;
        }
    }

    @Override
    public void connect(SocketAddress ignored) throws IOException {
        connect(ignored, 0);
    }

    private final InputStream in = new InputStream() {
        private final byte[] one = new byte[1];

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] target, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            return open().read(ByteBuffer.wrap(target, offset, length));
        }

        @Override
        public void close() {
            AmqpSocket.this.close();
        }
    };

    private final OutputStream out = new OutputStream() {
        @Override
        public void write(int value) throws IOException {
            write(new byte[] {(byte) value}, 0, 1);
        }

        @Override
        public void write(byte[] source, int offset, int length) throws IOException {
            synchronized (writing) {
                if (rewritten) {
                    open().write(ByteBuffer.wrap(source, offset, length));
                    return;
                }
                handshake(source, offset, length);
            }
        }

        @Override
        public void close() {
            AmqpSocket.this.close();
        }
    };

    /** Before Start-Ok: the protocol header through, frames collected and passed one by one. */
    private void handshake(byte[] source, int offset, int length) throws IOException {
        int at = offset;
        int end = offset + length;
        if (headerLeft > 0) {
            int n = Math.min(headerLeft, end - at);
            open().write(ByteBuffer.wrap(source, at, n));
            headerLeft -= n;
            at += n;
        }
        while (at < end && !rewritten) {
            frame.write(source[at++]);
            byte[] bytes = frame.toByteArray();
            if (bytes.length < 7) {
                continue;
            }
            long size = ((bytes[3] & 0xffL) << 24) | ((bytes[4] & 0xff) << 16)
                    | ((bytes[5] & 0xff) << 8) | (bytes[6] & 0xff);
            if (size > MAX_HANDSHAKE_FRAME) {
                throw new IOException("a handshake frame of " + size + " bytes from the client");
            }
            if (bytes.length < 7 + size + 1) {
                continue;
            }
            frame.reset();
            if (bytes[0] == FRAME_METHOD && bytes[1] == 0 && bytes[2] == 0 && size >= 4
                    && bytes[7] == 0 && bytes[8] == 10 && bytes[9] == 0 && bytes[10] == 11) {
                startOk(bytes, (int) size);
                rewritten = true;
            } else {
                open().write(ByteBuffer.wrap(bytes));
            }
        }
        if (at < end) {
            open().write(ByteBuffer.wrap(source, at, end - at));
        }
    }

    /** Connection.Start-Ok, written again with the real PLAIN response. */
    private void startOk(byte[] bytes, int size) throws IOException {
        int payload = 7;
        int at = payload + 4;                                        // class, method
        int table = readInt(bytes, at);
        at += 4 + table;
        int mechanismLength = bytes[at] & 0xff;
        String mechanism = new String(bytes, at + 1, mechanismLength, StandardCharsets.US_ASCII); // seclume-allow: AMQP handshake frame with the placeholder - no secret
        at += 1 + mechanismLength;
        if (!mechanism.equals("PLAIN")) {
            throw new IOException("the RabbitMQ client chose " + mechanism + " rather than PLAIN; "
                    + "SeclumeRabbit's connection factory sets PLAIN - it was changed");
        }
        int responseLength = readInt(bytes, at);
        byte[] response = Arrays.copyOfRange(bytes, at + 4, at + 4 + responseLength);
        byte[] expected = ("\0" + settings.user + "\0" + SeclumeRabbit.PLACEHOLDER)
                .getBytes(StandardCharsets.UTF_8); // seclume-allow: the user and the placeholder - no secret
        if (!Arrays.equals(response, expected)) {
            throw new IOException("the RabbitMQ client was given a user or password of its own; "
                    + "that password is a String on the heap already and is not sent. Leave "
                    + "user and password to the seclume URL");
        }
        int restFrom = at + 4 + responseLength;
        int restLength = payload + size - restFrom;
        byte[] user = settings.user.getBytes(StandardCharsets.UTF_8); // seclume-allow: the user name, which is public
        space.seclume.jfr.Observed.secretUse("rabbitmq", settings.host + ":" + settings.port,
                "plain");
        try (SecretScope password = SecretScope.fromProvider(settings.secret)) {
            MemorySegment secret = password.segment();
            for (int i = 0; i < password.length(); i++) {
                if (secret.get(ValueLayout.JAVA_BYTE, i) == 0) {
                    throw new IOException("the password holds a NUL, which SASL PLAIN cannot carry");
                }
            }
            int newResponse = 1 + user.length + 1 + password.length();
            int newSize = (at - payload) + 4 + newResponse + restLength;
            int total = 7 + newSize + 1;
            try (SecretScope rewrittenFrame = SecretScope.allocate(total)) {
                MemorySegment w = rewrittenFrame.segment();
                int p = 0;
                w.set(ValueLayout.JAVA_BYTE, p++, FRAME_METHOD);
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) 0);
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) 0);
                p = putInt(w, p, newSize);
                MemorySegment.copy(bytes, payload, w, ValueLayout.JAVA_BYTE, p, at - payload);
                p += at - payload;
                p = putInt(w, p, newResponse);
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) 0);
                MemorySegment.copy(user, 0, w, ValueLayout.JAVA_BYTE, p, user.length);
                p += user.length;
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) 0);
                MemorySegment.copy(secret, 0, w, p, password.length());
                p += password.length();
                MemorySegment.copy(bytes, restFrom, w, ValueLayout.JAVA_BYTE, p, restLength);
                p += restLength;
                w.set(ValueLayout.JAVA_BYTE, p++, FRAME_END);
                open().write(w.asSlice(0, p).asByteBuffer());
            }
        }
    }

    private static int readInt(byte[] b, int at) {
        return ((b[at] & 0xff) << 24) | ((b[at + 1] & 0xff) << 16) | ((b[at + 2] & 0xff) << 8)
                | (b[at + 3] & 0xff);
    }

    /** Big-endian, byte by byte into native memory - a length derived from the password. */
    private static int putInt(MemorySegment w, int at, int value) {
        w.set(ValueLayout.JAVA_BYTE, at, (byte) (value >>> 24));
        w.set(ValueLayout.JAVA_BYTE, at + 1, (byte) (value >>> 16));
        w.set(ValueLayout.JAVA_BYTE, at + 2, (byte) (value >>> 8));
        w.set(ValueLayout.JAVA_BYTE, at + 3, (byte) value);
        return at + 4;
    }

    private TlsLayer open() throws IOException {
        TlsLayer current = tls;
        if (current == null || closed) {
            throw new SocketException(closed ? "closed" : "not connected");
        }
        return current;
    }

    // ---- what the RabbitMQ client asks of a socket ------------------------------

    @Override
    public InputStream getInputStream() throws IOException {
        open();
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        open();
        return out;
    }

    @Override
    public void setSoTimeout(int millis) throws SocketException {
        timeout = millis;
        SocketTransport current = transport;
        if (current != null) {
            try {
                current.networkTimeout(millis);
            } catch (IOException e) {
                throw new SocketException(e.getMessage());
            }
        }
    }

    @Override
    public int getSoTimeout() {
        return timeout;
    }

    @Override
    public void setTcpNoDelay(boolean on) {
        // seclume's transport sets it itself
    }

    @Override
    public void setSoLinger(boolean on, int linger) {
        // the TLS close is seclume's
    }

    @Override
    public boolean isConnected() {
        return tls != null;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public boolean isBound() {
        return tls != null;
    }

    @Override
    public int getPort() {
        return settings.port;
    }

    @Override
    public InetAddress getInetAddress() {
        try {
            return InetAddress.getByName(settings.host);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    @Override
    public void shutdownInput() {
        close();
    }

    @Override
    public void shutdownOutput() {
        close();
    }

    @Override
    public void close() {
        closed = true;
        TlsLayer current = tls;
        if (current != null) {
            try {
                current.close();
            } catch (Exception ignored) {
                // closing anyway
            }
        }
        SocketTransport raw = transport;
        if (raw != null) {
            raw.close();
        }
    }

    @Override
    public String toString() {
        return "AmqpSocket[" + settings + (closed ? ", closed" : "") + "]";
    }
}
