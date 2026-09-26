package space.seclume.redis;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;

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

    /** One line of an answer, without its CRLF - for the login, before Jedis reads anything. */
    String readLine() throws IOException {
        StringBuilder line = new StringBuilder(); // seclume-allow: a server's status line, never a secret
        int c;
        while ((c = in.read()) >= 0 && c != '\n') {
            if (c != '\r') {
                line.append((char) c);
            }
            if (line.length() > 512) {
                throw new IOException("an answer line longer than 512 bytes during the login");
            }
        }
        if (c < 0) {
            throw new IOException("Redis closed the connection during the login");
        }
        return line.toString();
    }

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
