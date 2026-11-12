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
    /** The last four bytes of the head so far - CR LF CR LF ends it. */
    private int headTail;

    SessionTokenSocket(Socket plain, String host, int port, TlsLayer tls) {
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

    private static final int BLANK_LINE = 0x0D0A0D0A;

    /**
     * Follows what the client writes, a run of bytes at a time: a head is
     * kept until its blank line, everything else goes on to TLS as far as it
     * reaches in this write - a chunk's size line is one record, not one for
     * each of its bytes.
     */
    private void consume(byte[] source, int offset, int length) throws IOException {
        int at = offset;
        int end = offset + length;
        while (at < end) {
            switch (state) {
                case HEAD -> {
                    int from = at;
                    boolean ended = false;
                    while (at < end && !ended) {
                        headTail = (headTail << 8) | (source[at++] & 0xff);
                        ended = headTail == BLANK_LINE;
                    }
                    head.write(source, from, at - from);
                    if (ended) {
                        headTail = 0;
                        sendHead();
                    }
                }
                case BODY, CHUNK_DATA, CHUNK_END -> {
                    int n = (int) Math.min(remaining, end - at);
                    tls.write(ByteBuffer.wrap(source, at, n));
                    at += n;
                    remaining -= n;
                    if (remaining == 0) {
                        switch (state) {
                            case BODY -> state = State.HEAD;
                            case CHUNK_DATA -> {
                                state = State.CHUNK_END;
                                remaining = 2;
                            }
                            default -> state = State.CHUNK_SIZE;
                        }
                    }
                }
                case CHUNK_SIZE, TRAILER -> {
                    int from = at;
                    boolean ended = false;
                    while (at < end && !ended) {
                        byte b = source[at++];
                        line.write(b);
                        ended = b == '\n';
                    }
                    tls.write(ByteBuffer.wrap(source, from, at - from));
                    if (ended) {
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
        try (SecretScope rewritten = withToken(bytes, text, placeholder -> {
            TemporaryCredentials.Generation generation =
                    TemporaryCredentials.byPlaceholder(placeholder);
            return generation == null ? null : generation.token;
        })) {
            if (rewritten == null) {
                tls.write(ByteBuffer.wrap(bytes));
                return;
            }
            space.seclume.jfr.Observed.secretUse("aws", host + ":" + port, "session-token");
            ByteBuffer buffer = rewritten.segment().asSlice(0, rewritten.length()).asByteBuffer();
            while (buffer.hasRemaining()) {
                tls.write(buffer);
            }
        }
    }

    private static final String TOKEN_HEADER = "\r\nx-amz-security-token:";

    /**
     * The head with the session token written into its
     * {@code X-Amz-Security-Token} header, in native memory - or null when
     * that header is not there or holds no placeholder of ours.
     *
     * <p>Only that header's value. The placeholder is not a secret - the SDK
     * holds it, on the heap - and found anywhere in the head, as it once was,
     * one in the request target or in another header (an {@code x-amz-meta-}
     * value an application took from its user, say) would have had the token
     * written there: signed as the placeholder, refused by AWS, and the token
     * sent back in the error's canonical request. Anywhere else it stays what
     * it is. Two token headers are refused before anything is written.
     *
     * @param text  the head in lower case, byte for byte (ISO-8859-1)
     * @param token the token for a placeholder, or null for one whose credentials are gone
     */
    static SecretScope withToken(byte[] bytes, String text,
            java.util.function.Function<String, SecretScope> token) throws IOException {
        int header = text.indexOf(TOKEN_HEADER);
        if (header < 0) {
            return null;
        }
        if (text.indexOf(TOKEN_HEADER, header + 2) >= 0) {
            throw new IOException("two X-Amz-Security-Token headers in one request");
        }
        int lineEnd = text.indexOf("\r\n", header + TOKEN_HEADER.length());
        int from = header + TOKEN_HEADER.length();
        while (from < lineEnd && (bytes[from] == ' ' || bytes[from] == '\t')) {
            from++;
        }
        int to = lineEnd;
        while (to > from && (bytes[to - 1] == ' ' || bytes[to - 1] == '\t')) {
            to--;
        }
        if (to - from <= PREFIX.length || indexOf(bytes, PREFIX, from) != from) {
            return null;
        }
        // seclume-allow: the placeholder - no secret
        String placeholder = new String(bytes, from, to - from, StandardCharsets.US_ASCII);
        SecretScope secret = token.apply(placeholder);
        if (secret == null) {
            throw new IOException("a session token placeholder whose credentials are gone - the "
                    + "request was signed too long ago");
        }
        int tail = bytes.length - to;
        int total = from + secret.length() + tail;
        SecretScope rewritten = SecretScope.allocate(total);
        try {
            MemorySegment w = rewritten.segment();
            MemorySegment.copy(bytes, 0, w, ValueLayout.JAVA_BYTE, 0, from);
            MemorySegment.copy(secret.segment(), 0, w, from, secret.length());
            MemorySegment.copy(bytes, to, w, ValueLayout.JAVA_BYTE, from + secret.length(), tail);
            rewritten.length(total);
            return rewritten;
        } catch (RuntimeException e) {
            rewritten.close();
            throw e;
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
            long value = Long.parseLong(text, radix);
            if (value < 0) {
                throw new IOException("the HTTP client wrote a length below zero: '" + text
                        + "'");
            }
            return value;
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
