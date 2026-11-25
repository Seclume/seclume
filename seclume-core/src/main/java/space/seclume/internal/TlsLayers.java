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
 * <p>SQL Server's TDS 7.4 runs its handshake <em>inside</em> TDS packets, and
 * that nesting is TLS 1.2 by construction: {@link #startTls12} offers the own
 * stack's TLS 1.2 profile alone, over a transport the driver provides for the
 * packets.
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
        return watched(transport, () -> startNow(stack, transport, host, port, verify, identity,
                alpn));
    }

    /** One handshake, for {@link #watched}. */
    private interface Handshake {
        TlsLayer run() throws IOException;
    }

    /**
     * The handshake under a deadline of its own: {@code seclume.loginBudgetFactor}
     * (3) times the transport's network timeout. That timeout counts only
     * silence, and a server that sends a byte before each one ran out held
     * the handshake for as long as it liked. The deadline is the handshake's
     * and ends with it - a connection being migrated later never meets it.
     * No network timeout, no deadline: zero waits for ever, as before.
     */
    private static TlsLayer watched(Transport transport, Handshake handshake) throws IOException {
        int millis = transport.networkTimeoutMillis();
        if (millis <= 0) {
            return handshake.run();
        }
        long budget = millis * (long) Math.max(1, Integer.getInteger("seclume.loginBudgetFactor", 3));
        // 0 running, 1 done, 2 the deadline came first.
        java.util.concurrent.atomic.AtomicInteger state = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.ScheduledFuture<?> watch = Transports.after(budget, () -> {
            if (state.compareAndSet(0, 2)) {
                transport.close();
            }
        });
        TlsLayer layer = null;
        try {
            layer = handshake.run();
        } catch (IOException | RuntimeException failure) {
            if (state.get() == 2) {
                throw new IOException("the TLS handshake did not finish within " + budget
                        + " ms (seclume.loginBudgetFactor x the network timeout) - the server "
                        + "kept it going without completing it", failure);
            }
            throw failure;
        } finally {
            watch.cancel(false);
        }
        if (!state.compareAndSet(0, 1)) {
            closeQuietly(layer);
            throw new IOException("the TLS handshake did not finish within " + budget + " ms");
        }
        return layer;
    }

    private static TlsLayer startNow(TlsStack stack, Transport transport, String host, int port,
            boolean verify, ClientIdentity identity, String alpn) throws IOException {
        // AUTO is the default and means the own stack: TLS 1.3, and the TLS 1.2
        // profile for a server without it. JSSE only when asked for by name.
        if (stack == TlsStack.AUTO) {
            stack = TlsStack.SECLUME;
        }
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
            try {
                // seclume-verify --print-pin: the certificate, and no further.
                TrustChoice.certificateOnly(layer);
            } catch (IOException taken) {
                closeQuietly(layer);
                layer = null;
                throw taken;
            }
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
            authenticated(layer, verify || pinned);
            return layer;
        } finally {
            space.seclume.jfr.Observed.endHandshake(event, host + ":" + port,
                    stack.name().toLowerCase(java.util.Locale.ROOT),
                    layer == null ? null : layer.description());
        }
    }

    /**
     * The own stack offering TLS 1.2 alone - for a handshake that cannot be
     * TLS 1.3, which today is SQL Server's TDS 7.4. Pins and the trust choice
     * apply exactly as in {@link #start}.
     */
    public static TlsLayer startTls12(Transport transport, String host, int port, boolean verify,
            ClientIdentity identity) throws IOException {
        return watched(transport, () -> startTls12Now(transport, host, port, verify, identity));
    }

    private static TlsLayer startTls12Now(Transport transport, String host, int port,
            boolean verify, ClientIdentity identity) throws IOException {
        space.seclume.jfr.SeclumeEvents.TlsHandshake event =
                space.seclume.jfr.Observed.beginHandshake();
        TlsLayer layer = null;
        boolean pinned = TrustChoice.pinned();
        try {
            layer = SeclumeTls.startOffering(transport, host, verify && !pinned, identity,
                    space.seclume.tls.ClientHello.Offer.TLS12);
            try {
                // seclume-verify --print-pin: the certificate, and no further.
                TrustChoice.certificateOnly(layer);
            } catch (IOException taken) {
                closeQuietly(layer);
                layer = null;
                throw taken;
            }
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
            authenticated(layer, verify || pinned);
            return layer;
        } finally {
            space.seclume.jfr.Observed.endHandshake(event, host + ":" + port, "seclume",
                    layer == null ? null : layer.description());
        }
    }

    /** A pin compared, or a chain and host name checked: the server is who it says. */
    private static void authenticated(TlsLayer layer, boolean checked) {
        if (layer instanceof SeclumeTls own) {
            own.authenticated(checked);
        } else if (layer instanceof TlsChannel jdk) {
            jdk.authenticated(checked);
        }
    }

    private static void closeQuietly(TlsLayer layer) {
        try {
            layer.close();
        } catch (Exception ignored) {
            // ended either way
        }
    }

    private static TlsLayer jsse(Transport transport, String host, int port, boolean verify,
            String alpn) throws IOException {
        TlsChannel started = TlsChannel.create(transport, host, port, verify, alpn);
        started.handshake();
        return started;
    }
}
