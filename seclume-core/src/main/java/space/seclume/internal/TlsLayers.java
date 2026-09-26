package space.seclume.internal;

import java.io.IOException;

import space.seclume.internal.jdbc.TlsStack;
import space.seclume.tls.ClientIdentity;

/**
 * Starts TLS on a connected transport, with whichever stack was asked for.
 *
 * <p>Three of the four protocols reach TLS the same way - negotiate in the
 * clear, then hand the socket over - and each of them used to build an
 * {@code SSLEngine} itself. One place instead, so that adding a stack is one
 * change rather than three, and so that the choice is visibly the same choice
 * in all three drivers.
 *
 * <p>SQL Server is not here. Its handshake runs <em>inside</em> TDS packets
 * and is TLS 1.2 by construction - TDS 7.4 has no other shape - so it cannot
 * use a TLS 1.3 client at all. Moving it needs TDS 8.0, where TLS wraps the
 * whole connection from the first byte, and that is a protocol change rather
 * than a substitution. See {@code TdsTls}.
 */
public final class TlsLayers {

    private TlsLayers() {
    }

    /**
     * Runs the handshake and returns the layer every byte then travels
     * through.
     *
     * @param verify whether the certificate chain and the host name are
     *               checked; {@code false} is encryption without
     *               authentication
     */
    public static TlsLayer start(TlsStack stack, Transport transport, String host, int port,
            boolean verify) throws IOException {
        return start(stack, transport, host, port, verify, null);
    }

    /**
     * The same, proving who the client is as well.
     *
     * <p>An identity is only possible on {@link TlsStack#SECLUME}, and the
     * reason is the whole point of the work: reaching a client certificate
     * through JSSE means a {@code KeyManager}, and a {@code KeyManager} hands
     * out a {@link java.security.PrivateKey} - the key back on the heap, which
     * is the one thing this must not do. So rather than quietly ignoring an
     * identity on the JSSE path, that combination is refused.
     */
    public static TlsLayer start(TlsStack stack, Transport transport, String host, int port,
            boolean verify, ClientIdentity identity) throws IOException {
        return start(stack, transport, host, port, verify, identity, null);
    }

    /**
     * The same, offering one application protocol and requiring it back.
     *
     * <p>One caller: TDS 8.0, where {@code tds/8.0} is how SQL Server knows
     * what arrived on its port. Both stacks refuse a server that does not
     * select it, because the alternative failure - a connection that hangs
     * while each side waits for the other - is much harder to read.
     */
    public static TlsLayer start(TlsStack stack, Transport transport, String host, int port,
            boolean verify, ClientIdentity identity, String alpn) throws IOException {
        if (identity != null && stack != TlsStack.SECLUME) {
            throw new IOException("a client certificate was configured, but this connection "
                    + "uses the JDK's TLS - reaching a client key through JSSE would put it on "
                    + "the heap, which is what seclume exists to avoid. Add tlsStack=seclume");
        }
        // Recorded here rather than in each of the three channels: this is
        // the one place both stacks pass through, and the handshake is worth
        // separating from the connection it belongs to because it is slow for
        // reasons outside this process - a distant CA, an OCSP lookup.
        space.seclume.jfr.SeclumeEvents.TlsHandshake event =
                space.seclume.jfr.Observed.beginHandshake();
        TlsLayer layer = null;
        // A pinned key is the trust: no chain and no host name to check, the
        // key compared once the handshake has shown it.
        boolean pinned = TrustChoice.pinned();
        boolean checkChain = verify && !pinned;
        try {
            layer = stack == TlsStack.SECLUME
                    ? SeclumeTls.start(transport, host, checkChain, identity, alpn)
                    : jsse(transport, host, port, checkChain, alpn);
            if (pinned) {
                try {
                    TrustChoice.checkPin(layer);
                } catch (IOException wrongKey) {
                    try {
                        layer.close();
                    } catch (Exception ignored) {
                        // refused either way
                    }
                    layer = null;
                    throw wrongKey;
                }
            }
            return layer;
        } finally {
            space.seclume.jfr.Observed.endHandshake(event, host + ":" + port,
                    stack.name().toLowerCase(java.util.Locale.ROOT),
                    layer == null ? null : layer.description());
        }
    }

    private static TlsLayer jsse(Transport transport, String host, int port, boolean verify,
            String alpn) throws IOException {
        TlsChannel started = TlsChannel.create(transport, host, port, verify, alpn);
        started.handshake();
        return started;
    }
}
