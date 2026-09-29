package space.seclume.internal;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.SQLException;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretScope;

/**
 * seclume's own TLS 1.3 client as an {@link SSLEngine} - for the clients
 * that take an engine rather than a socket: Kafka's
 * {@code ssl.engine.factory.class}, and Netty's {@code SslHandler} under
 * Lettuce.
 *
 * <p><b>Why an engine of our own.</b> The JDK's engine keeps the plaintext it
 * encrypts in heap buffers it never wipes; a password sent through it is on
 * the heap whatever the client did. Here the keys stay in native memory as in
 * every other seclume connection, and {@link Outgoing} lets the caller put a
 * secret into what goes out at the last moment: the client library is given
 * a placeholder, and the placeholder is replaced by bytes from a
 * {@link SecretScope} on their way into the cipher. The secret is never a
 * heap object - not in the library, not in its buffers, not here.
 *
 * <p><b>How a blocking stack becomes an engine.</b> The handshake runs on a
 * virtual thread of its own over an {@link EnginePipe}: what {@code unwrap} is
 * given goes into the pipe, and every call waits until that thread needs the
 * peer again or is done, so it never asks its caller to run a delegated task.
 * After the handshake the connection is driven from {@code wrap} and
 * {@code unwrap} themselves, one whole record at a time.
 *
 * <p>Client mode only, TLS 1.3 only, and the server's certificate and host
 * name are always checked - against the JVM's trust store, or the
 * {@code tlsRootCert} / {@code tlsPin} the {@link TrustChoice.Choice} names.
 */
public final class SeclumeSslEngine extends SSLEngine {

    /** The most one record carries. */
    public static final int MAX_PLAINTEXT = 1 << 14;
    /** One record on the wire: header, plaintext, content type, tag. */
    private static final int MAX_RECORD = 5 + MAX_PLAINTEXT + 1 + 16;
    private static final int PACKET_BUFFER = 5 + MAX_PLAINTEXT + 256;
    private static final long HANDSHAKE_STEP_MILLIS = 30_000;
    private static final String[] SUITES = {"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"};
    private static final String[] PROTOCOLS = {"TLSv1.3"};

    /**
     * Looks at the plaintext before it is encrypted, and may replace part of
     * it - the placeholder of a secret by the secret. One per engine, called
     * by one thread at a time, with the bytes in the order they go out.
     */
    public interface Outgoing {

        /**
         * What to do with the next bytes: send {@code unchanged} of them as
         * they are, or replace the first {@code replaced} with
         * {@code replacement}, which the engine encrypts and then closes.
         * Neither may be more than {@link #MAX_PLAINTEXT} bytes.
         */
        record Step(int unchanged, int replaced, SecretScope replacement) {

            public static Step unchanged(int count) {
                return new Step(count, 0, null);
            }

            public static Step replace(int consumed, SecretScope replacement) {
                return new Step(0, consumed, replacement);
            }
        }

        /**
         * The next step for {@code plain}, from its position - which is not
         * to be moved; at least one byte is there.
         */
        Step next(ByteBuffer plain) throws IOException;
    }

    private final TrustChoice.Choice trust;
    private final Outgoing outgoing;
    private final EnginePipe pipe = new EnginePipe();
    private final Session session = new Session();
    private volatile TlsLayer layer;
    private volatile Exception failure;
    private boolean started;
    private boolean handshakeOver;
    private boolean outboundClosed;
    private boolean inboundDone;

    /**
     * @param host     the server's name, for SNI and the certificate check
     * @param trust    whom to trust instead of the JVM's store, or null
     * @param outgoing what may replace bytes on their way out, or null
     */
    public SeclumeSslEngine(String host, int port, TrustChoice.Choice trust, Outgoing outgoing) {
        super(host, port);
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("a TLS engine that checks the server needs its "
                    + "host name");
        }
        this.trust = trust;
        this.outgoing = outgoing;
    }

    // ---- the handshake ------------------------------------------------------

    @Override
    public synchronized void beginHandshake() throws SSLException {
        if (handshakeOver) {
            throw new SSLException("TLS 1.3 has no renegotiation");
        }
        start();
    }

    private void start() throws SSLException {
        if (started) {
            return;
        }
        if (outboundClosed) {
            throw new SSLException("the TLS engine is closed");
        }
        started = true;
        String host = getPeerHost();
        int port = getPeerPort();
        Thread.ofVirtual().name("seclume-tls-handshake " + host).start(() -> {
            try {
                layer = TrustChoice.using(trust, () -> {
                    try {
                        return TlsLayers.start(TlsStack.SECLUME, pipe, host, port, true);
                    } catch (IOException e) {
                        throw new SQLException(e.getMessage(), "08001", e);
                    }
                });
            } catch (SQLException e) {
                failure = e.getCause() instanceof Exception cause ? cause : e;
            } catch (RuntimeException e) {
                failure = e;
            } finally {
                pipe.handshakeDone();
            }
        });
        quiet();
    }

    private void quiet() throws SSLException {
        if (!pipe.awaitQuiet(HANDSHAKE_STEP_MILLIS)) {
            throw new SSLHandshakeException("the TLS handshake with " + getPeerHost()
                    + " made no progress for " + HANDSHAKE_STEP_MILLIS / 1000 + " s");
        }
    }

    private void checkFailure() throws SSLException {
        Exception failed = failure;
        if (failed != null) {
            SSLHandshakeException refused = new SSLHandshakeException("TLS handshake with "
                    + getPeerHost() + ":" + getPeerPort() + " failed: " + failed.getMessage());
            refused.initCause(failed);
            throw refused;
        }
    }

    /** The handshake thread finished well and everything it wrote has been taken. */
    private boolean handshakeCompleted() {
        return layer != null && pipe.pendingOut() == 0;
    }

    @Override
    public synchronized HandshakeStatus getHandshakeStatus() {
        if (!started || handshakeOver) {
            return HandshakeStatus.NOT_HANDSHAKING;
        }
        if (pipe.pendingOut() > 0 || layer != null) {
            // Also when it finished with nothing left to send: the next wrap
            // reports FINISHED, which is what callers wait for.
            return HandshakeStatus.NEED_WRAP;
        }
        return HandshakeStatus.NEED_UNWRAP;
    }

    private SSLEngineResult finished(int consumed, int produced) {
        handshakeOver = true;
        pipe.stopBlocking();
        return new SSLEngineResult(Status.OK, HandshakeStatus.FINISHED, consumed, produced);
    }

    // ---- wrap ---------------------------------------------------------------

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length,
                                             ByteBuffer dst) throws SSLException {
        if (!outboundClosed) {
            start();
        }
        if (!handshakeOver && !outboundClosed) {
            int produced = pipe.drain(dst);
            if (produced == 0 && pipe.pendingOut() > 0) {
                return new SSLEngineResult(Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
            }
            checkFailure();
            if (handshakeCompleted()) {
                return finished(0, produced);
            }
            return new SSLEngineResult(Status.OK, getHandshakeStatus(), 0, produced);
        }
        if (outboundClosed) {
            int produced = pipe.drain(dst);
            if (produced == 0 && pipe.pendingOut() > 0) {
                return new SSLEngineResult(Status.BUFFER_OVERFLOW,
                        HandshakeStatus.NOT_HANDSHAKING, 0, 0);
            }
            return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0,
                    produced);
        }
        // A KeyUpdate answer written while reading goes first.
        int produced = pipe.drain(dst);
        if (pipe.pendingOut() > 0) {
            return new SSLEngineResult(produced == 0 ? Status.BUFFER_OVERFLOW : Status.OK,
                    HandshakeStatus.NOT_HANDSHAKING, 0, produced);
        }
        ByteBuffer src = firstWithRemaining(srcs, offset, length);
        if (src == null) {
            return new SSLEngineResult(Status.OK, HandshakeStatus.NOT_HANDSHAKING, 0, produced);
        }
        if (dst.remaining() < MAX_RECORD) {
            return new SSLEngineResult(produced == 0 ? Status.BUFFER_OVERFLOW : Status.OK,
                    HandshakeStatus.NOT_HANDSHAKING, 0, produced);
        }
        int consumed;
        try {
            Outgoing.Step step = outgoing == null
                    ? Outgoing.Step.unchanged(Math.min(src.remaining(), MAX_PLAINTEXT))
                    : outgoing.next(src);
            if (step.replacement() != null) {
                try (SecretScope bytes = step.replacement()) {
                    if (step.replaced() <= 0 || step.replaced() > src.remaining()
                            || bytes.length() > MAX_PLAINTEXT) {
                        throw new IllegalStateException("a replacement of " + step.replaced()
                                + " bytes by " + bytes.length() + " does not fit one record");
                    }
                    layer.write(bytes.segment().asSlice(0, bytes.length()).asByteBuffer());
                }
                consumed = step.replaced();
            } else {
                consumed = step.unchanged();
                if (consumed <= 0 || consumed > src.remaining() || consumed > MAX_PLAINTEXT) {
                    throw new IllegalStateException("cannot send " + consumed + " of "
                            + src.remaining() + " bytes in one record");
                }
                layer.write(src.slice(src.position(), consumed));
            }
        } catch (IOException e) {
            throw new SSLException("could not encrypt for " + getPeerHost() + ": "
                    + e.getMessage(), e);
        }
        src.position(src.position() + consumed);
        produced += pipe.drain(dst);
        return new SSLEngineResult(Status.OK, HandshakeStatus.NOT_HANDSHAKING, consumed,
                produced);
    }

    // ---- unwrap -------------------------------------------------------------

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset,
                                               int length) throws SSLException {
        if (inboundDone || outboundClosed) {
            return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }
        start();
        if (!handshakeOver) {
            checkFailure();
            int consumed = 0;
            for (int n; (n = EnginePipe.recordLength(src)) > 0; ) {
                pipe.feed(src, n);
                consumed += n;
            }
            if (consumed == 0) {
                return new SSLEngineResult(Status.BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
            }
            quiet();
            checkFailure();
            if (handshakeCompleted()) {
                return finished(consumed, 0);
            }
            return new SSLEngineResult(Status.OK, getHandshakeStatus(), consumed, 0);
        }
        ByteBuffer dst = firstWithRemaining(dsts, offset, length);
        if (dst == null) {
            dst = dsts[offset];
        }
        int consumed = 0;
        int record = pipe.nextRecordLength();
        if (record == 0) {
            record = EnginePipe.recordLength(src);
            if (record == 0) {
                return new SSLEngineResult(Status.BUFFER_UNDERFLOW,
                        HandshakeStatus.NOT_HANDSHAKING, 0, 0);
            }
            // Room for all the record can hold, checked before it is taken.
            if (dst.remaining() < Math.min(MAX_PLAINTEXT, record - 5 - 16)) {
                return new SSLEngineResult(Status.BUFFER_OVERFLOW,
                        HandshakeStatus.NOT_HANDSHAKING, 0, 0);
            }
            pipe.feed(src, record);
            consumed = record;
        } else if (dst.remaining() < Math.min(MAX_PLAINTEXT, record - 5 - 16)) {
            return new SSLEngineResult(Status.BUFFER_OVERFLOW, HandshakeStatus.NOT_HANDSHAKING,
                    0, 0);
        }
        int produced = 0;
        try {
            int read = layer.read(dst);
            if (read < 0) {
                inboundDone = true;
                return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING,
                        consumed, 0);
            }
            produced = read;
        } catch (EnginePipe.WouldBlock handledHere) {
            // a record for the connection itself - a session ticket, a KeyUpdate
        } catch (IOException e) {
            throw new SSLException("could not decrypt from " + getPeerHost() + ": "
                    + e.getMessage(), e);
        }
        return new SSLEngineResult(Status.OK, pipe.pendingOut() > 0 ? HandshakeStatus.NEED_WRAP
                : HandshakeStatus.NOT_HANDSHAKING, consumed, produced);
    }

    private static ByteBuffer firstWithRemaining(ByteBuffer[] buffers, int offset, int length) {
        for (int i = offset; i < offset + length; i++) {
            if (buffers[i].hasRemaining()) {
                return buffers[i];
            }
        }
        return null;
    }

    // ---- closing ------------------------------------------------------------

    @Override
    public synchronized void closeOutbound() {
        if (outboundClosed) {
            return;
        }
        outboundClosed = true;
        release();
    }

    @Override
    public synchronized boolean isOutboundDone() {
        return outboundClosed && pipe.pendingOut() == 0;
    }

    @Override
    public synchronized void closeInbound() {
        inboundDone = true;
        release();
    }

    @Override
    public synchronized boolean isInboundDone() {
        return inboundDone;
    }

    /** The connection's keys freed - a close_notify, if one could be written, stays to be sent. */
    private void release() {
        TlsLayer open = layer;
        if (open != null) {
            open.close();                       // writes close_notify, then closes the pipe
            return;
        }
        pipe.close();                           // ends a handshake still waiting for the peer
        if (started) {
            pipe.awaitQuiet(HANDSHAKE_STEP_MILLIS);
            open = layer;                       // finished in the meantime
            if (open != null) {
                open.close();
            }
        }
    }

    // ---- what an engine is asked about itself ---------------------------------

    @Override
    public Runnable getDelegatedTask() {
        return null;                            // every step is done in wrap and unwrap
    }

    @Override
    public synchronized SSLSession getSession() {
        return session;
    }

    @Override
    public String getApplicationProtocol() {
        return "";
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return SUITES.clone();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return SUITES.clone();
    }

    /** Ignored: the suites are TLS 1.3's AES-GCM pair, always. */
    @Override
    public void setEnabledCipherSuites(String[] suites) {
    }

    @Override
    public String[] getSupportedProtocols() {
        return PROTOCOLS.clone();
    }

    @Override
    public String[] getEnabledProtocols() {
        return PROTOCOLS.clone();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        for (String protocol : protocols) {
            if (protocol.equals("TLSv1.3")) {
                return;
            }
        }
        throw new IllegalArgumentException("seclume's TLS speaks TLS 1.3 only, and "
                + String.join(", ", protocols) + " leaves it out");
    }

    @Override
    public void setUseClientMode(boolean clientMode) {
        if (!clientMode) {
            throw new IllegalArgumentException("seclume's TLS engine is a client only");
        }
    }

    @Override
    public boolean getUseClientMode() {
        return true;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {
    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean enable) {
    }

    @Override
    public boolean getEnableSessionCreation() {
        return true;
    }

    /** What callers read after the handshake: protocol, suite, the server's certificate, sizes. */
    private final class Session implements SSLSession {

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
        }

        @Override
        public boolean isValid() {
            return layer != null;
        }

        @Override
        public void putValue(String name, Object value) {
        }

        @Override
        public Object getValue(String name) {
            return null;
        }

        @Override
        public void removeValue(String name) {
        }

        @Override
        public String[] getValueNames() {
            return new String[0];
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            X509Certificate leaf = leaf();
            if (leaf == null) {
                throw new SSLPeerUnverifiedException("no server certificate yet");
            }
            return new Certificate[] {leaf};
        }

        @Override
        public Certificate[] getLocalCertificates() {
            return null;
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            X509Certificate leaf = leaf();
            if (leaf == null) {
                throw new SSLPeerUnverifiedException("no server certificate yet");
            }
            return leaf.getSubjectX500Principal();
        }

        @Override
        public Principal getLocalPrincipal() {
            return null;
        }

        private X509Certificate leaf() {
            TlsLayer open = layer;
            try {
                return open == null ? null : open.peerCertificate();
            } catch (IOException e) {
                return null;
            }
        }

        @Override
        public String getCipherSuite() {
            TlsLayer open = layer;
            if (open == null) {
                return "SSL_NULL_WITH_NULL_NULL";
            }
            // "TLSv1.3 / TLS_AES_256_GCM_SHA384 (seclume)"
            String description = open.description();
            int slash = description.indexOf(" / ");
            if (slash < 0) {
                return SUITES[0];
            }
            String suite = description.substring(slash + 3);
            int space = suite.indexOf(' ');
            return space < 0 ? suite : suite.substring(0, space);
        }

        @Override
        public String getProtocol() {
            return "TLSv1.3";
        }

        @Override
        public String getPeerHost() {
            return SeclumeSslEngine.this.getPeerHost();
        }

        @Override
        public int getPeerPort() {
            return SeclumeSslEngine.this.getPeerPort();
        }

        @Override
        public int getPacketBufferSize() {
            return PACKET_BUFFER;
        }

        @Override
        public int getApplicationBufferSize() {
            return MAX_PLAINTEXT;
        }
    }
}
