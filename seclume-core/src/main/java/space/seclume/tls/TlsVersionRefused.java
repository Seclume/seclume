package space.seclume.tls;

import java.io.IOException;

/**
 * The server cannot speak this client's TLS - neither TLS 1.3 nor the TLS 1.2
 * profile (ECDHE on P-256, AES-GCM) - and said so before its ServerHello was
 * accepted.
 *
 * <p>Its own type because it says something different from "something is
 * wrong": the server is reachable and speaks TLS, only not a version or suite
 * this client offers. Nothing about the server has been authenticated at that
 * point, and nothing secret has been sent, so the cause carries no
 * certificate verdict - a certificate the client refuses is never one of
 * these.
 *
 * <p>The cause is what actually happened: the peer's alert, the alert this
 * client sent, or the connection ending.
 */
public final class TlsVersionRefused extends IOException {

    private static final long serialVersionUID = 1L;

    public TlsVersionRefused(IOException cause) {
        super("the server speaks neither TLS 1.3 nor TLS 1.2 with ECDHE on P-256 and "
                + "AES-GCM - " + cause.getMessage() + ". A server limited to older suites can be "
                + "reached with tlsStack=jsse, at the cost of the password passing through "
                + "the heap", cause);
    }
}
