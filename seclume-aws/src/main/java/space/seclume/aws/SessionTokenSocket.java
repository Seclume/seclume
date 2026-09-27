package space.seclume.aws;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.cert.Certificate;
import java.sql.SQLException;
import java.util.Locale;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.Transport;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretScope;

/**
 * The TLS socket the SDK's HTTP client gets for an AWS endpoint: seclume's
 * TLS 1.3 over the TCP connection the client opened, and one change to what
 * the client writes.
 *
 * <p>With temporary credentials the SDK holds a placeholder where the session
 * token goes, and writes it into {@code X-Amz-Security-Token}. This socket
 * follows the HTTP/1.1 framing of what is written - request head, then a body
 * of {@code Content-Length} bytes or in chunks - and in each <b>head</b>
 * writes the real token, from native memory, where the placeholder stands.
 * Bodies go through untouched, whatever they contain.
 */
final class SessionTokenSocket extends SSLSocket {

    private static final byte[] PREFIX =
            TemporaryCredentials.TOKEN_PREFIX.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the placeholder's prefix - no secret

    private enum State { HEAD, BODY, CHUNK_SIZE, CHUNK_DATA, CHUNK_END, TRAILER }

    private final Socket plain;
    private final String host;
    private final int port;
    private final TlsLayer tls;
    private final Object writing = new Object();
    private volatile boolean closed;

    private State state = State.HEAD;
    private final ByteArrayOutputStream head = new ByteArrayOutputStream();
    private final ByteArrayOutputStream line = new ByteArrayOutputStream();
    private long remaining;

    private SessionTokenSocket(Socket plain, String host, int port, TlsLayer tls) {
        this.plain = plain;
        this.host = host;
        this.port = port;
        this.tls = tls;
    }

    /** TLS over {@code plain}, the server's certificate checked against {@code host}. */
    static SessionTokenSocket over(Socket plain, String host, int port, TrustChoice.Choice trust)
            throws IOException {
        Transport transport = new SocketStreams(plain);
        try {
            TlsLayer tls = TrustChoice.using(trust, () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, transport, host, port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
            return new SessionTokenSocket(plain, host, port, tls);
        } catch (SQLException e) {
            plain.close();
            throw e.getCause() instanceof IOException io ? io : new IOException(e.getMessage(), e);
        }
    }

    // ---- what is written ------------------------------------------------------------

    private final OutputStream out = new OutputStream() {
        @Override
        public void write(int value) throws IOException {
            write(new byte[] {(byte) value}, 0, 1);
        }

        @Override
        public void write(byte[] source, int offset, int length) throws IOException {
            synchronized (writing) {
                consume(source, offset, length);
            }
        }

        @Override
        public void close() throws IOException {
            SessionTokenSocket.this.close();
        }
    };

    private void consume(byte[] source, int offset, int length) throws IOException {
        int at = offset;
        int end = offset + length;
        while (at < end) {
            switch (state) {
                case HEAD -> {
                    head.write(source[at++]);
                    if (endsWithBlankLine(head)) {
                        sendHead();
                    }
                }
                case BODY, CHUNK_DATA -> {
                    int n = (int) Math.min(remaining, end - at);
                    tls.write(ByteBuffer.wrap(source, at, n));
                    at += n;
                    remaining -= n;
                    if (remaining == 0) {
                        state = state == State.BODY ? State.HEAD : State.CHUNK_END;
                        remaining = 2;
                    }
                }
                case CHUNK_END -> {
                    tls.write(ByteBuffer.wrap(source, at++, 1));
                    if (--remaining == 0) {
                        state = State.CHUNK_SIZE;
                    }
                }
                case CHUNK_SIZE, TRAILER -> {
                    byte b = source[at];
                    tls.write(ByteBuffer.wrap(source, at++, 1));
                    line.write(b);
                    if (b == '\n') {
                        String text = line.toString(StandardCharsets.US_ASCII).trim();
                        line.reset();
                        if (state == State.TRAILER) {
                            if (text.isEmpty()) {
                                state = State.HEAD;
                            }
                        } else {
                            int semicolon = text.indexOf(';');
                            long size = number(semicolon < 0 ? text
                                    : text.substring(0, semicolon).trim(), 16);
                            if (size == 0) {
                                state = State.TRAILER;
                            } else {
                                state = State.CHUNK_DATA;
                                remaining = size;
                            }
                        }
                    }
                }
                default -> throw new IllegalStateException(state.name());
            }
        }
    }

    private static boolean endsWithBlankLine(ByteArrayOutputStream head) {
        int size = head.size();
        if (size < 4) {
            return false;
        }
        byte[] bytes = head.toByteArray();
        return bytes[size - 4] == '\r' && bytes[size - 3] == '\n' && bytes[size - 2] == '\r'
                && bytes[size - 1] == '\n';
    }

    /** The request head, with the token written where its placeholder is. */
    private void sendHead() throws IOException {
        byte[] bytes = head.toByteArray();
        head.reset();
        String text = new String(bytes, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT); // seclume-allow: a request head with the placeholder - no secret
        long length = header(text, "content-length");
        if (text.contains("\r\ntransfer-encoding: chunked")) {
            state = State.CHUNK_SIZE;
        } else if (length > 0) {
            state = State.BODY;
            remaining = length;
        } else {
            state = State.HEAD;
        }
        int found = indexOf(bytes, PREFIX, 0);
        if (found < 0) {
            tls.write(ByteBuffer.wrap(bytes));
            return;
        }
        space.seclume.jfr.Observed.secretUse("aws", host + ":" + port, "session-token");
        int placeholderEnd = found;
        while (placeholderEnd < bytes.length && bytes[placeholderEnd] != '\r') {
            placeholderEnd++;
        }
        // seclume-allow: the placeholder - no secret
        String placeholder = new String(bytes, found, placeholderEnd - found,
                StandardCharsets.US_ASCII).trim();
        TemporaryCredentials.Generation generation =
                TemporaryCredentials.byPlaceholder(placeholder);
        if (generation == null) {
            throw new IOException("a session token placeholder whose credentials are gone - the "
                    + "request was signed too long ago");
        }
        SecretScope token = generation.token;
        int tail = bytes.length - placeholderEnd;
        try (SecretScope rewritten = SecretScope.allocate(found + token.length() + tail)) {
            MemorySegment w = rewritten.segment();
            MemorySegment.copy(bytes, 0, w, ValueLayout.JAVA_BYTE, 0, found);
            MemorySegment.copy(token.segment(), 0, w, found, token.length());
            MemorySegment.copy(bytes, placeholderEnd, w, ValueLayout.JAVA_BYTE,
                    found + token.length(), tail);
            ByteBuffer buffer = w.asSlice(0, found + token.length() + tail).asByteBuffer();
            while (buffer.hasRemaining()) {
                tls.write(buffer);
            }
        }
        if (indexOf(bytes, PREFIX, placeholderEnd) >= 0) {
            throw new IOException("two session token placeholders in one request");
        }
    }

    private static long header(String head, String name) throws IOException {
        int at = head.indexOf("\r\n" + name + ":");
        if (at < 0) {
            return -1;
        }
        int end = head.indexOf("\r\n", at + 2);
        return number(head.substring(at + name.length() + 3, end).trim(), 10);
    }

    /** A length the client wrote - not one, and the framing cannot be followed. */
    private static long number(String text, int radix) throws IOException {
        try {
            return Long.parseLong(text, radix);
        } catch (NumberFormatException e) {
            throw new IOException("the HTTP client wrote a length that is not a number: '"
                    + text + "'", e);
        }
    }

    private static int indexOf(byte[] data, byte[] pattern, int from) {
        outer:
        for (int i = from; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    // ---- what is read ---------------------------------------------------------------

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
            return tls.read(ByteBuffer.wrap(target, offset, length));
        }

        @Override
        public void close() throws IOException {
            SessionTokenSocket.this.close();
        }
    };

    @Override
    public InputStream getInputStream() throws IOException {
        if (closed) {
            throw new SocketException("this AWS connection has been closed");
        }
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (closed) {
            throw new SocketException("this AWS connection has been closed");
        }
        return out;
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        try {
            tls.close();
        } catch (Exception ignored) {
            // closing anyway
        }
        plain.close();
    }

    @Override
    public boolean isClosed() {
        return closed || plain.isClosed();
    }

    @Override
    public boolean isConnected() {
        return plain.isConnected();
    }

    @Override
    public boolean isBound() {
        return plain.isBound();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        plain.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return plain.getSoTimeout();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        plain.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return plain.getTcpNoDelay();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        plain.setKeepAlive(on);
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        plain.setSoLinger(on, linger);
    }

    @Override
    public InetAddress getInetAddress() {
        return plain.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return plain.getLocalAddress();
    }

    @Override
    public int getPort() {
        return plain.getPort();
    }

    @Override
    public int getLocalPort() {
        return plain.getLocalPort();
    }

    @Override
    public java.net.SocketAddress getRemoteSocketAddress() {
        return plain.getRemoteSocketAddress();
    }

    @Override
    public java.net.SocketAddress getLocalSocketAddress() {
        return plain.getLocalSocketAddress();
    }

    @Override
    public void shutdownInput() throws IOException {
        close();
    }

    @Override
    public void shutdownOutput() throws IOException {
        close();
    }

    // ---- what SSLSocket asks; the TLS is seclume's and already done ---------------

    @Override
    public String[] getSupportedCipherSuites() {
        return new String[] {"TLS_AES_128_GCM_SHA256"};
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return getSupportedCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        // seclume's TLS chooses
    }

    @Override
    public String[] getSupportedProtocols() {
        return new String[] {"TLSv1.3"};
    }

    @Override
    public String[] getEnabledProtocols() {
        return getSupportedProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        // seclume's TLS is 1.3
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        // the handshake is over before the socket is handed out
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        // nothing was added
    }

    @Override
    public void startHandshake() {
        // done in over()
    }

    @Override
    public void setUseClientMode(boolean mode) {
        // always a client
    }

    @Override
    public boolean getUseClientMode() {
        return true;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        // a client
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        // a client
    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        // one connection, one session
    }

    @Override
    public boolean getEnableSessionCreation() {
        return true;
    }

    /** What little a caller may ask about the session - the certificate was checked by seclume. */
    private final SSLSession session = new SSLSession() {
        private final long created = System.currentTimeMillis();

        @Override
        public byte[] getId() {
            return new byte[0];
        }

        @Override
        public SSLSessionContext getSessionContext() {
            return null;
        }

        @Override
        public long getCreationTime() {
            return created;
        }

        @Override
        public long getLastAccessedTime() {
            return created;
        }

        @Override
        public void invalidate() {
            // one connection
        }

        @Override
        public boolean isValid() {
            return !closed;
        }

        @Override
        public void putValue(String name, Object value) {
            // nothing kept
        }

        @Override
        public Object getValue(String name) {
            return null;
        }

        @Override
        public void removeValue(String name) {
            // nothing kept
        }

        @Override
        public String[] getValueNames() {
            return new String[0];
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            throw new SSLPeerUnverifiedException("checked by seclume's TLS, not handed out");
        }

        @Override
        public Certificate[] getLocalCertificates() {
            return null;
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            throw new SSLPeerUnverifiedException("checked by seclume's TLS, not handed out");
        }

        @Override
        public Principal getLocalPrincipal() {
            return null;
        }

        @Override
        public String getCipherSuite() {
            return "TLS_AES_128_GCM_SHA256";
        }

        @Override
        public String getProtocol() {
            return "TLSv1.3";
        }

        @Override
        public String getPeerHost() {
            return host;
        }

        @Override
        public int getPeerPort() {
            return port;
        }

        @Override
        public int getPacketBufferSize() {
            return 16 * 1024 + 256;
        }

        @Override
        public int getApplicationBufferSize() {
            return 16 * 1024;
        }
    };

    /** The client's TCP connection as a seclume transport. */
    private static final class SocketStreams implements Transport {

        private final Socket socket;
        private final InputStream input;
        private final OutputStream output;
        private final byte[] buffer = new byte[16 * 1024 + 256];

        SocketStreams(Socket socket) throws IOException {
            this.socket = socket;
            this.input = socket.getInputStream();
            this.output = socket.getOutputStream();
        }

        @Override
        public int read(ByteBuffer into) throws IOException {
            int n = input.read(buffer, 0, Math.min(buffer.length, into.remaining()));
            if (n > 0) {
                into.put(buffer, 0, n);
            }
            return n;
        }

        @Override
        public int write(ByteBuffer from) throws IOException {
            int n = Math.min(buffer.length, from.remaining());
            byte[] chunk = new byte[n];
            from.get(chunk);
            output.write(chunk);
            output.flush();
            return n;
        }

        @Override
        public void networkTimeout(int millis) throws IOException {
            socket.setSoTimeout(millis);
        }

        @Override
        public boolean isOpen() {
            return !socket.isClosed();
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (IOException e) {
                // closing anyway
            }
        }
    }
}
