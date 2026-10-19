package space.seclume.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
 * A TLS socket - seclume's TLS 1.3 - for any HTTP/1.1 client, which writes
 * secrets where the client wrote their placeholders.
 *
 * <p>The client is given placeholders ({@link SeclumeSslSocketFactory#placeholder})
 * instead of a token or a password, and builds its requests with them. This
 * socket follows the HTTP/1.1 framing of what is written - request head, then
 * a body of {@code Content-Length} bytes or in chunks - and in each
 * <b>head</b>:
 *
 * <ul>
 *   <li>writes the secret where a placeholder stands - a bearer token, an API
 *       key header;
 *   <li>writes {@code Basic base64(user:secret)} where the client wrote
 *       {@code Basic base64(user:placeholder)} - decoded and encoded again in
 *       native memory.
 * </ul>
 *
 * <p>Bodies go through untouched, whatever they contain.
 */
final class CredentialSocket extends SSLSocket {

    private final Socket plain;
    private final String host;
    private final int port;
    private final TlsLayer tls;
    private final Object writing = new Object();
    private volatile boolean closed;

    private final HttpFraming framing = new HttpFraming();
    /** For HTTP/2 - negotiated by ALPN - the frames are followed instead. */
    private final Http2Requests http2;

    private CredentialSocket(Socket plain, String host, int port, TlsLayer tls, boolean http2) {
        this.plain = plain;
        this.host = host;
        this.port = port;
        this.tls = tls;
        this.http2 = http2 ? new Http2Requests(this::write, host + ":" + port) : null;
    }

    /**
     * TLS over {@code plain}, the server's certificate checked against {@code
     * host}; with {@code http2}, offering and requiring {@code h2}.
     */
    static CredentialSocket over(Socket plain, String host, int port, TrustChoice.Choice trust,
                                 boolean http2) throws IOException {
        Transport transport = new SocketStreams(plain);
        try {
            TlsLayer tls = TrustChoice.using(trust, () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, transport, host, port, true, null,
                            http2 ? "h2" : null);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
            return new CredentialSocket(plain, host, port, tls, http2);
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
            CredentialSocket.this.close();
        }
    };

    private void consume(byte[] source, int offset, int length) throws IOException {
        if (http2 != null) {
            http2.consume(source, offset, length);
            return;
        }
        int at = offset;
        int end = offset + length;
        while (at < end) {
            if (framing.inHead()) {
                byte[] complete = framing.headByte(source[at++]);
                if (complete != null) {
                    sendHead(complete);
                }
            } else {
                int n = framing.passThrough(ByteBuffer.wrap(source, at, end - at),
                        Integer.MAX_VALUE);
                tls.write(ByteBuffer.wrap(source, at, n));
                at += n;
            }
        }
    }

    /** The request head, with the secrets written where their placeholders are. */
    private void sendHead(byte[] bytes) throws IOException {
        if (!HttpFraming.carriesPlaceholder(bytes)) {
            write(ByteBuffer.wrap(bytes));
            return;
        }
        String text = new String(bytes, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT); // seclume-allow: a request head with placeholders - no secret
        space.seclume.jfr.Observed.secretUse("http", host + ":" + port,
                text.contains(": basic ") ? "basic" : "header");
        try (SecretScope out = HttpFraming.rewrite(bytes)) {
            write(out.segment().asSlice(0, out.length()).asByteBuffer());
        }
    }

    private void write(ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            tls.write(buffer);
        }
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
            CredentialSocket.this.close();
        }
    };

    @Override
    public InputStream getInputStream() throws IOException {
        if (closed) {
            throw new SocketException("this connection has been closed");
        }
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (closed) {
            throw new SocketException("this connection has been closed");
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

    /** {@code h2} if it was asked for - and the server agreed - else HTTP/1.1, without ALPN. */
    @Override
    public String getApplicationProtocol() {
        return http2 != null ? "h2" : "";
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return getApplicationProtocol();
    }

    /** Whether {@code session} is one of this socket's - the hostname was checked by seclume. */
    static boolean ours(SSLSession session) {
        return session != null && session.getClass().getEnclosingClass() == CredentialSocket.class;
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
