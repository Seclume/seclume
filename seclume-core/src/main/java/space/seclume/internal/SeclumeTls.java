package space.seclume.internal;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import space.seclume.tls.CertificateTrust;
import space.seclume.tls.ClientHandshake;
import space.seclume.tls.ClientIdentity;
import space.seclume.tls.TlsConnection;

/**
 * This project's own TLS 1.3 client, in the shape the drivers already speak.
 *
 * <p>A thin adapter and nothing more: {@link TlsConnection} is a
  * {@link Transport} because that is the seam it goes into, and
 * {@link TlsLayer} is what the four protocols call. The two differ in one
 * place - a {@code Transport} may write part of a buffer, a {@code TlsLayer}
 * writes all of it - and that is the whole of what this class does.
 *
 * <p><b>What it changes for a driver.</b> Two things, and only one of them is
 * visible. The traffic secrets never become Java objects, which is the
 * property the rest of the library is about and which an {@code SSLEngine}
 * cannot offer at any price. And the connection can be frozen: the encryption
 * state is ours, in memory we allocated, so it can be written out and taken up
 * elsewhere. An {@code SSLEngine}'s cannot, which is why mTLS with an off-heap
 * key and a connection that survives moving house are the same piece of work.
 *
 * <p><b>What it costs.</b> One key exchange group, one signature scheme for
 * client certificates, no resumption, no TLS 1.2. A server that wants any of
 * those is a server for the JSSE stack, which is why that one stays the
 * default and this is chosen per connection.
 */
public final class SeclumeTls implements TlsLayer {

    private final TlsConnection connection;

    private SeclumeTls(TlsConnection connection) {
        this.connection = connection;
    }

    /**
     * Runs the handshake over an already connected transport.
     *
     * @param verify   whether the certificate chain and the host name are
     *                 checked. {@code false} is encryption without
     *                 authentication - the caller has to have decided that
     * @param identity a client certificate to present if the server asks for
     *                 one, or {@code null}. Passing one forces nothing: a
     *                 server that does not ask never sees it
     */
    public static SeclumeTls start(Transport transport, String host, boolean verify,
            ClientIdentity identity) throws IOException {
        return start(transport, host, verify, identity, null);
    }

    /**
     * The same, offering one application protocol and requiring it back.
     *
     * @param alpn the protocol name, or null. Today only {@code tds/8.0}
     *             uses it - see {@link ClientHandshake}
     */
    public static SeclumeTls start(Transport transport, String host, boolean verify,
            ClientIdentity identity, String alpn) throws IOException {
        if (alpn == null) {
            return startWithoutAlpn(transport, host, verify, identity);
        }
        CertificateTrust trust = verify ? defaultTrust() : null;
        return new SeclumeTls(ClientHandshake.connect(transport, host, trust, identity, alpn));
    }

    private static CertificateTrust defaultTrust() throws IOException {
        try {
            return CertificateTrust.ofDefaultTrustStore();
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot read the trust store, so no certificate could be "
                    + "checked: " + e.getMessage(), e);
        }
    }

    private static SeclumeTls startWithoutAlpn(Transport transport, String host, boolean verify,
            ClientIdentity identity) throws IOException {
        if (!verify) {
            return new SeclumeTls(identity == null
                    ? ClientHandshake.connectWithoutAuthenticating(transport, host)
                    : ClientHandshake.connectWithoutAuthenticating(transport, host, identity));
        }
        CertificateTrust trust = defaultTrust();
        return new SeclumeTls(identity == null
                ? ClientHandshake.connect(transport, host, trust)
                : ClientHandshake.connect(transport, host, trust, identity));
    }

    @Override
    public void write(ByteBuffer plain) throws IOException {
        while (plain.hasRemaining()) {
            connection.write(plain);
        }
    }

    @Override
    public int read(ByteBuffer target) throws IOException {
        return connection.read(target);
    }

    @Override
    public X509Certificate peerCertificate() {
        return connection.peerCertificate();
    }

    /**
     * Protocol, cipher suite, and <b>which stack</b> - the last part is not
     * decoration.
     *
     * <p>Both stacks negotiate TLS 1.3 with the same suites against the same
     * server, so without this a report cannot tell them apart, and neither
     * can a test: one asserting only {@code TLSv1.3} would stay green if this
     * stack were never reached at all. An operator has the same problem for
     * the same reason.
     */
    @Override
    public String description() {
        return connection.description() + " (seclume)";
    }

    /**
     * Yes - which is half the reason this class exists.
     *
     * <p>{@code TlsConnection.freeze} writes the traffic secrets and the
     * record sequence numbers out, and {@code thaw} takes them up over a
     * transport that reaches the same peer. The peer is told nothing and
     * notices nothing; if any of it is wrong the very next record fails its
     * tag, which is what makes it safe to attempt at all.
     */
    @Override
    public boolean movable() {
        return true;
    }

    @Override
    public void replaceTransport(Transport replacement) {
        connection.replaceTransport(replacement);
    }

    /** The connection underneath - for whoever has to freeze it. */
    public TlsConnection connection() {
        return connection;
    }

    @Override
    public void discard() {
        connection.discard();
    }

    @Override
    public void close() {
        connection.close();
    }
}
