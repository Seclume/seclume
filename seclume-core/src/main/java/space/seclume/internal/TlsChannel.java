package space.seclume.internal;

import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * TLS over a socket, for the protocols that put it there.
 *
 * <p>PostgreSQL, MySQL and Oracle all switch the whole connection to TLS after
 * a short negotiation in the clear: from that point every byte of the protocol
 * travels inside TLS records. That is the ordinary arrangement, and this class
 * is the ordinary implementation of it — an {@code SSLEngine} between the wire
 * buffers and the socket.
 *
 * <p>SQL Server is the exception and has its own: there the handshake runs
 * <em>inside</em> TDS packets and the nesting inverts afterwards. See
 * {@code TdsTls}.
 *
 * <p><b>Every buffer here is direct.</b> The login travels through them, and a
 * heap buffer would put it where the whole library exists to keep it from. That
 * is also why the plaintext is never copied into a {@code byte[]} on the way —
 * it goes from the caller's buffer into {@code wrap} and no further.
 */
public final class TlsChannel implements AutoCloseable {

    private static final ByteBuffer EMPTY = ByteBuffer.allocateDirect(0);

    private final SSLEngine engine;
    private final SocketChannel channel;

    private final ByteBuffer netOut;
    private final ByteBuffer netIn;
    private final ByteBuffer appIn;

    private TlsChannel(SSLEngine engine, SocketChannel channel) {
        this.engine = engine;
        this.channel = channel;
        SSLSession session = engine.getSession();
        this.netOut = ByteBuffer.allocateDirect(session.getPacketBufferSize());
        this.netIn = ByteBuffer.allocateDirect(session.getPacketBufferSize());
        this.appIn = ByteBuffer.allocateDirect(session.getApplicationBufferSize());
        this.netIn.limit(0);
        this.appIn.limit(0);
    }

    /**
     * Prepares TLS on an already connected socket.
     *
     * @param verify whether the server's certificate and its name are checked.
     *               {@code false} gives encryption without authentication — it
     *               stops a passive listener and not a man in the middle, and
     *               the caller has to have said so on purpose.
     */
    public static TlsChannel create(SocketChannel channel, String host, int port, boolean verify)
            throws IOException {
        try {
            SSLContext context;
            if (verify) {
                context = SSLContext.getDefault();
            } else {
                context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[] {new TrustEverything()}, null);
            }
            SSLEngine engine = context.createSSLEngine(host, port);
            engine.setUseClientMode(true);
            if (verify) {
                SSLParameters parameters = engine.getSSLParameters();
                // Without this the certificate is checked against the trust
                // store but not against the host that was dialled - which
                // leaves exactly the hole the certificate was meant to close.
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                engine.setSSLParameters(parameters);
            }
            return new TlsChannel(engine, channel);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("cannot set up TLS: " + e.getMessage(), e);
        }
    }

    /** Runs the handshake; afterwards every byte goes through TLS. */
    public void handshake() throws IOException {
        engine.beginHandshake();
        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
        while (status != SSLEngineResult.HandshakeStatus.FINISHED
                && status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch (status) {
                case NEED_WRAP -> {
                    netOut.clear();
                    SSLEngineResult result = engine.wrap(EMPTY, netOut);
                    status = result.getHandshakeStatus();
                    if (result.getStatus() != SSLEngineResult.Status.OK) {
                        throw new IOException("TLS wrap failed: " + result.getStatus());
                    }
                    netOut.flip();
                    writeFully(netOut);
                }
                case NEED_UNWRAP -> {
                    if (!netIn.hasRemaining()) {
                        receive();
                    }
                    appIn.clear();
                    SSLEngineResult result = engine.unwrap(netIn, appIn);
                    appIn.flip();
                    status = result.getHandshakeStatus();
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        receive();
                        status = engine.getHandshakeStatus();
                    }
                }
                case NEED_TASK -> {
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    status = engine.getHandshakeStatus();
                }
                default -> throw new IOException("unexpected TLS handshake state: " + status);
            }
        }
        netIn.clear();
        netIn.limit(0);
        appIn.clear();
        appIn.limit(0);
    }

    /** Encrypts and sends everything remaining in {@code plain}. */
    public void write(ByteBuffer plain) throws IOException {
        while (plain.hasRemaining()) {
            netOut.clear();
            SSLEngineResult result = engine.wrap(plain, netOut);
            if (result.getStatus() != SSLEngineResult.Status.OK) {
                throw new IOException("TLS wrap failed: " + result.getStatus());
            }
            netOut.flip();
            writeFully(netOut);
        }
    }

    /**
     * Reads decrypted bytes into {@code target}.
     *
     * @return how many bytes were put there, never zero unless the target was
     *         full; -1 when the peer closed the connection
     */
    public int read(ByteBuffer target) throws IOException {
        if (appIn.hasRemaining()) {
            return copyOut(target);
        }
        while (true) {
            if (!netIn.hasRemaining() && receive() < 0) {
                return -1;
            }
            appIn.clear();
            SSLEngineResult result = engine.unwrap(netIn, appIn);
            appIn.flip();
            switch (result.getStatus()) {
                case OK -> {
                    if (appIn.hasRemaining()) {
                        return copyOut(target);
                    }
                }
                case BUFFER_UNDERFLOW -> {
                    if (receive() < 0) {
                        return -1;
                    }
                }
                case CLOSED -> {
                    return -1;
                }
                default -> throw new IOException("TLS unwrap failed: " + result.getStatus());
            }
        }
    }

    private int copyOut(ByteBuffer target) {
        int count = Math.min(target.remaining(), appIn.remaining());
        int limit = appIn.limit();
        appIn.limit(appIn.position() + count);
        target.put(appIn);
        appIn.limit(limit);
        return count;
    }

    /** Pulls more ciphertext from the socket, keeping what is already there. */
    private int receive() throws IOException {
        netIn.compact();
        int read = channel.read(netIn);
        netIn.flip();
        if (read < 0) {
            throw new IOException("the server closed the connection during TLS");
        }
        return read;
    }

    private void writeFully(ByteBuffer source) throws IOException {
        while (source.hasRemaining()) {
            channel.write(source);
        }
    }

    /**
     * The server's certificate - for channel binding, not for checking.
     *
     * <p>Available whatever the TLS mode: with {@code require} the
     * certificate is not verified, but it is still the certificate of this
     * connection, and that is all a binding needs.
     */
    public java.security.cert.X509Certificate peerCertificate() throws IOException {
        try {
            java.security.cert.Certificate[] chain = engine.getSession().getPeerCertificates();
            if (chain.length == 0 || !(chain[0] instanceof java.security.cert.X509Certificate x)) {
                throw new IOException("the server sent no X.509 certificate");
            }
            return x;
        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            throw new IOException("the server sent no certificate: " + e.getMessage(), e);
        }
    }

    public String protocol() {
        return engine.getSession().getProtocol();
    }

    public String cipherSuite() {
        return engine.getSession().getCipherSuite();
    }

    @Override
    public void close() {
        engine.closeOutbound();
    }

    /**
     * Accepts any certificate — encryption without authentication.
     *
     * <p>Only reachable when the caller asked for it. It is a real setting with
     * a real use (a test container with a self-signed certificate), and it is
     * also a real hole, which is why it has to be named rather than defaulted
     * into.
     */
    private static final class TrustEverything extends X509ExtendedTrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String type) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String type) {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String type, Socket socket) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String type, Socket socket) {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String type, SSLEngine engine) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String type, SSLEngine engine) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
