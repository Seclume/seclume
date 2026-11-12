package space.seclume.redis;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.secret.SecretProvider;

/**
 * A {@link Socket} for Jedis over a seclume connection - plain, or through
 * seclume's own TLS. Jedis uses a socket for its two streams, its timeout and
 * whether it is still open; those are what this answers.
 */
final class TransportSocket extends Socket {

    private final SocketTransport transport;
    private final TlsLayer tls;
    private final InetSocketAddress remote;
    private volatile boolean closed;
    private int timeout;

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
            int n = receive(ByteBuffer.wrap(target, offset, length));
            return n;
        }
    };

    private final OutputStream out = new OutputStream() {
        @Override
        public void write(int value) throws IOException {
            write(new byte[] {(byte) value}, 0, 1);
        }

        @Override
        public void write(byte[] source, int offset, int length) throws IOException {
            send(ByteBuffer.wrap(source, offset, length));
        }
    };

    TransportSocket(SocketTransport transport, TlsLayer tls, String host, int port) {
        this.transport = transport;
        this.tls = tls;
        this.remote = InetSocketAddress.createUnresolved(host, port);
    }

    /** Writes everything in {@code bytes}, encrypted when the connection is. */
    void send(ByteBuffer bytes) throws IOException {
        check();
        if (tls != null) {
            tls.write(bytes);
        } else {
            while (bytes.hasRemaining()) {
                transport.write(bytes);
            }
        }
    }

    private int receive(ByteBuffer into) throws IOException {
        check();
        try {
            int n = tls != null ? tls.read(into) : transport.read(into);
            return n;
        } catch (IOException e) {
            if (timeout > 0 && !transport.isOpen() && !closed) {
                throw new SocketTimeoutException("no answer from Redis within " + timeout
                        + " ms");
            }
            throw e;
        }
    }

    /**
     * One line of an answer, without its CRLF - for the login, before Jedis
     * reads anything. Read into native memory, and an error searched there
     * for the secrets before it becomes a {@code String}: a server that does
     * not know the command answers with its arguments, the password among
     * them (see {@link RespReplyGuard}).
     */
    String readLine(SecretProvider... secrets) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment line = arena.allocate(LONGEST_LINE + 2);
            ByteBuffer view = line.asByteBuffer();
            int length = 0;
            while (true) {
                view.limit(length + 1).position(length);
                int n = receive(view);
                if (n < 0) {
                    throw new IOException("Redis closed the connection during the login");
                }
                if (n == 0) {
                    continue;
                }
                if (line.get(ValueLayout.JAVA_BYTE, length) == '\n') {
                    break;
                }
                if (++length > LONGEST_LINE) {
                    throw new IOException("an answer line longer than " + LONGEST_LINE
                            + " bytes during the login");
                }
            }
            if (length > 0 && line.get(ValueLayout.JAVA_BYTE, length - 1) == '\r') {
                length--;
            }
            int end = length;
            if (end > 0 && line.get(ValueLayout.JAVA_BYTE, 0) == '-') {
                RespReplyGuard.mask(new RespReplyGuard.Bytes() {
                    @Override
                    public int length() {
                        return end;
                    }

                    @Override
                    public byte get(int index) {
                        return line.get(ValueLayout.JAVA_BYTE, index);
                    }

                    @Override
                    public void set(int index, byte value) {
                        line.set(ValueLayout.JAVA_BYTE, index, value);
                    }
                }, 1, end, secrets);
            }
            StringBuilder text = new StringBuilder(end); // seclume-allow: a server's status line, the secret masked out of it
            for (int i = 0; i < end; i++) {
                text.append((char) (line.get(ValueLayout.JAVA_BYTE, i) & 0xff));
            }
            return text.toString();
        }
    }

    private static final int LONGEST_LINE = 512;

    private void check() throws IOException {
        if (closed) {
            throw new IOException("the socket is closed");
        }
    }

    @Override
    public InputStream getInputStream() {
        return in;
    }

    @Override
    public OutputStream getOutputStream() {
        return out;
    }

    @Override
    public synchronized void setSoTimeout(int millis) {
        timeout = millis;
        try {
            transport.networkTimeout(millis);
        } catch (IOException ignored) {
            // closed already: the next read says so
        }
    }

    @Override
    public synchronized int getSoTimeout() {
        return timeout;
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (tls != null) {
            try {
                tls.close();
            } catch (Exception ignored) {
                // the transport goes next either way
            }
        }
        transport.close();
    }

    @Override
    public boolean isClosed() {
        return closed || !transport.isOpen();
    }

    @Override
    public boolean isConnected() {
        return true;
    }

    @Override
    public boolean isBound() {
        return true;
    }

    @Override
    public boolean isInputShutdown() {
        return isClosed();
    }

    @Override
    public boolean isOutputShutdown() {
        return isClosed();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return remote;
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return null;
    }
}
