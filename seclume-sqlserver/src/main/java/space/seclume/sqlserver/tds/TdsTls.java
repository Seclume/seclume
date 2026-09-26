package space.seclume.sqlserver.tds;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * TLS inside TDS.
 *
 * <p>This is the peculiarity of SQL Server, and it is nested: during the
 * handshake the TLS records sit <b>inside</b> TDS packets of type
 * {@link Tds#TYPE_PRELOGIN}. Once the handshake is done it inverts - then the
 * TDS packets sit inside TLS records. Confuse the two and you get a handshake
 * that never completes.
 *
 * <p><b>Why this is not optional:</b> the password encoding in LOGIN7 is
 * reversible without a key (see {@code TdsPassword}). Without TLS the password
 * effectively travels in the clear. When the server answers
 * {@link Tds#ENCRYPT_OFF}, that does not mean "unencrypted" either - it means
 * "encrypt the login only".
 *
 * <p>All buffers are {@code allocateDirect}. That is not a performance
 * argument here but the whole point: the login packet with the password passes
 * through these buffers, and a heap buffer would show up in a heap dump.
 */
public final class TdsTls implements space.seclume.internal.TlsLayer {

    private final SSLEngine engine;
    /** Whether a tlsPin is the trust here - compared once the handshake shows the key. */
    private boolean pinned;
    /** Not final only so that {@link #replaceTransport} can do its job. */
    private space.seclume.internal.Transport channel;

    /** Grows when a flight or a record does not fit - see {@link #grown}. */
    private ByteBuffer netOut;
    private final ByteBuffer netIn;
    private final ByteBuffer appIn;
    /** An empty buffer for {@code wrap} during the handshake. */
    private static final ByteBuffer EMPTY = ByteBuffer.allocateDirect(0);

    private boolean handshakeDone;

    private TdsTls(SSLEngine engine, space.seclume.internal.Transport channel) {
        this.engine = engine;
        this.channel = channel;
        SSLSession session = engine.getSession();
        this.netOut = ByteBuffer.allocateDirect(session.getPacketBufferSize() + 64);
        this.netIn = ByteBuffer.allocateDirect(session.getPacketBufferSize() + 64);
        this.appIn = ByteBuffer.allocateDirect(session.getApplicationBufferSize() + 64);
        // Both receive buffers start out *empty*, not *writable*: a freshly
        // allocated ByteBuffer reports hasRemaining() == true because it has
        // room. Mistake that for "data is waiting" and you hand the SSLEngine
        // zero bytes instead of a TLS record - and get
        // "Unrecognized SSL message".
        this.appIn.limit(0);
        this.netIn.limit(0);
    }

    /**
     * Builds the layer.
     *
     * @param trustAnyCertificate if {@code true}, the server certificate is
     *        <b>not</b> verified. This exists for test setups with a
     *        self-signed certificate and makes TLS worthless against a man in
     *        the middle - the name says so plainly, so that nobody switches it
     *        on by accident.
     */
    public static TdsTls create(space.seclume.internal.Transport channel, String host, int port,
                                boolean trustAnyCertificate) throws IOException {
        try {
            // The same trust as every other connection (TlsLayers): a tlsPin is
            // the trust on its own, compared after the handshake; otherwise the
            // chain is checked against tlsRootCert or the JVM's store, AND the
            // certificate has to name the host dialled. This path used to take
            // the JVM's default context with no host name check, and ignored
            // tlsRootCert and tlsPin - on SQL Server's default TDS 7.4, and so
            // under the FEDAUTH token login too. Found in review, 25.09.2026.
            boolean pinned = space.seclume.internal.TrustChoice.pinned();
            SSLContext context;
            if (trustAnyCertificate || pinned) {
                context = SSLContext.getInstance("TLSv1.3");
                // Opt-in only (trustServerCertificate) - reported as unsafe by
                // seclume-verify. nosemgrep: java.lang.security.audit.crypto.ssl.insecure-trust-manager.insecure-trust-manager
                context.init(null, new TrustManager[] {new TrustEverything()}, null);
            } else {
                context = space.seclume.internal.TrustChoice.sslContext();
            }
            SSLEngine engine = context.createSSLEngine(host, port);
            engine.setUseClientMode(true);
            if (!trustAnyCertificate && !pinned) {
                javax.net.ssl.SSLParameters parameters = engine.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                engine.setSSLParameters(parameters);
            }
            // TLS 1.2, nothing newer: the handshake *inside* TDS is built
            // for 1.2. TLS 1.3 moves handshake messages past the finish, which
            // breaks this nesting - SQL Server supports 1.3 only with TDS 8.0,
            // where TLS sits outside and wraps the whole connection.
            engine.setEnabledProtocols(new String[] {"TLSv1.2"});
            TdsTls tls = new TdsTls(engine, channel);
            tls.pinned = pinned;
            return tls;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("cannot set up TLS", e);
        }
    }

    /**
     * Runs the handshake - with the TLS records inside TDS packets.
     */
    public void handshake() throws IOException {
        engine.beginHandshake();
        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
        while (status != SSLEngineResult.HandshakeStatus.FINISHED
                && status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch (status) {
                case NEED_WRAP -> {
                    // Collect every record of this flight and send them
                    // *together* in one TDS packet. Wrapped individually, SQL
                    // Server hangs up: it expects one message per flight, not
                    // one per TLS record.
                    netOut.clear();
                    do {
                        SSLEngineResult result = engine.wrap(EMPTY, netOut);
                        if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                            // A whole flight in one buffer: it can be larger
                            // than one record's worth - RDS SQL Server 2019's
                            // was, 26.09.2026. Keep what is there, grow, retry.
                            netOut = grown(netOut);
                            continue;
                        }
                        status = result.getHandshakeStatus();
                        if (result.getStatus() != SSLEngineResult.Status.OK) {
                            throw new IOException("TLS wrap failed: " + result.getStatus());
                        }
                    } while (status == SSLEngineResult.HandshakeStatus.NEED_WRAP);
                    netOut.flip();
                    if (netOut.hasRemaining()) {
                        sendInTdsPacket(netOut);
                    }
                }
                case NEED_UNWRAP -> {
                    if (!appIn.hasRemaining() && !netIn.hasRemaining()) {
                        receiveFromTdsPacket();
                    }
                    appIn.clear();
                    SSLEngineResult result = engine.unwrap(netIn, appIn);
                    appIn.flip();
                    status = result.getHandshakeStatus();
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        receiveFromTdsPacket();
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
        if (pinned) {
            java.security.cert.Certificate[] chain = engine.getSession().getPeerCertificates();
            space.seclume.internal.TrustChoice.checkPin(chain.length > 0
                    && chain[0] instanceof java.security.cert.X509Certificate first ? first : null);
        }
        handshakeDone = true;
        netIn.clear();
        netIn.limit(0);
        appIn.clear();
        appIn.limit(0);
    }

    /** One TLS record, wrapped in a TDS packet of type PRELOGIN. */
    private void sendInTdsPacket(ByteBuffer record) throws IOException {
        int length = Tds.HEADER_SIZE + record.remaining();
        ByteBuffer packet = ByteBuffer.allocateDirect(length);
        packet.put((byte) Tds.TYPE_PRELOGIN);
        packet.put((byte) Tds.STATUS_END_OF_MESSAGE);
        packet.put((byte) (length >>> 8));         // big-endian, as in the TDS header
        packet.put((byte) length);
        packet.putShort((short) 0);                // SPID
        packet.put((byte) 1);                      // packet number
        packet.put((byte) 0);                      // window
        packet.put(record);
        packet.flip();
        while (packet.hasRemaining()) {
            channel.write(packet);
        }
    }

    /** Takes the TLS record out of the next TDS packet. */
    private void receiveFromTdsPacket() throws IOException {
        ByteBuffer header = ByteBuffer.allocateDirect(Tds.HEADER_SIZE);
        readFully(header);
        header.flip();
        header.get();                              // type
        header.get();                              // status
        int length = ((header.get() & 0xff) << 8) | (header.get() & 0xff);
        int payload = length - Tds.HEADER_SIZE;
        if (payload < 0) {
            throw new IOException("the server announced a packet of " + length + " bytes");
        }
        netIn.clear();
        netIn.limit(payload);
        readFully(netIn);
        netIn.flip();
    }

    private void readFully(ByteBuffer target) throws IOException {
        while (target.hasRemaining()) {
            if (channel.read(target) < 0) {
                throw new IOException("the server closed the connection during the TLS handshake");
            }
        }
    }

    /** Twice the room, with what was written so far carried over. */
    private ByteBuffer grown(ByteBuffer full) {
        ByteBuffer bigger = ByteBuffer.allocateDirect(
                Math.max(full.capacity() * 2, engine.getSession().getPacketBufferSize() + 64));
        full.flip();
        bigger.put(full);
        return bigger;
    }

    // ---- after the handshake: TDS inside TLS -----------------------------

    /** Encrypts and sends; the plaintext stays in direct memory. */
    @Override
    public void write(ByteBuffer plain) throws IOException {
        requireHandshake();
        while (plain.hasRemaining()) {
            netOut.clear();
            SSLEngineResult result = engine.wrap(plain, netOut);
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                netOut = grown(netOut);
                continue;
            }
            if (result.getStatus() != SSLEngineResult.Status.OK) {
                throw new IOException("TLS wrap failed: " + result.getStatus());
            }
            netOut.flip();
            while (netOut.hasRemaining()) {
                channel.write(netOut);
            }
        }
    }

    /**
     * Reads decrypted into {@code target}.
     *
     * @return how many bytes were read, or -1 at the end
     */
    @Override
    public int read(ByteBuffer target) throws IOException {
        requireHandshake();
        if (appIn.hasRemaining()) {
            return copyOut(target);
        }
        while (true) {
            if (!netIn.hasRemaining()) {
                netIn.clear();
                int read = channel.read(netIn);
                if (read < 0) {
                    return -1;
                }
                netIn.flip();
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
                    // The record is not complete yet - read more.
                    netIn.compact();
                    int read = channel.read(netIn);
                    if (read < 0) {
                        return -1;
                    }
                    netIn.flip();
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

    private void requireHandshake() throws IOException {
        if (!handshakeDone) {
            throw new IOException("the TLS handshake has not finished");
        }
    }

    /**
     * Protocol and cipher suite.
     *
     * <p>No stack marker, unlike the two layers in the core: there is only
     * one implementation of this nesting and there is not going to be a
     * second, because TLS 1.3 cannot be nested this way at all. That is what
     * TDS 8.0 exists for.
     */
    @Override
    public String description() {
        return protocol() + " / " + cipherSuite();
    }

    /**
     * No. The keys are inside an {@code SSLEngine}, which will not give them
     * up - see {@link space.seclume.internal.TlsLayer#movable()}. On this
     * driver that is doubly settled: the nesting is TLS 1.2 by construction.
     */
    @Override
    public boolean movable() {
        return false;
    }

    @Override
    public java.security.cert.X509Certificate peerCertificate() throws IOException {
        try {
            java.security.cert.Certificate[] chain = engine.getSession().getPeerCertificates();
            if (chain.length == 0
                    || !(chain[0] instanceof java.security.cert.X509Certificate leaf)) {
                throw new IOException("the server sent no X.509 certificate");
            }
            return leaf;
        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            throw new IOException("the server sent no certificate: " + e.getMessage(), e);
        }
    }

    @Override
    public void replaceTransport(space.seclume.internal.Transport replacement) {
        this.channel = replacement;
    }

    /** The engine never owned the socket, so this is the same as closing. */
    @Override
    public void discard() {
        close();
    }

    @Override
    public void close() {
        engine.closeOutbound();
    }

    /** The negotiated protocol - for diagnostics. */
    public String protocol() {
        return engine.getSession().getProtocol();
    }

    public String cipherSuite() {
        return engine.getSession().getCipherSuite();
    }

    /**
     * Accepts any certificate.
     *
     * <p>For test setups only. In a real application this makes TLS worthless
     * against a man in the middle - and that attack is especially rewarding
     * with SQL Server, because the login packet carries the password
     * effectively in the clear.
     */
    private static final class TrustEverything implements X509TrustManager { // nosemgrep: java.lang.security.audit.crypto.ssl.insecure-trust-manager.insecure-trust-manager

        @Override // nosemgrep: java.lang.security.audit.crypto.ssl.insecure-trust-manager.insecure-trust-manager
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // deliberately empty - see the class comment
        }

        @Override // nosemgrep: java.lang.security.audit.crypto.ssl.insecure-trust-manager.insecure-trust-manager
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // deliberately empty - see the class comment
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
