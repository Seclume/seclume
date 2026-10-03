package space.seclume.tls;

import java.io.IOException;

/**
 * The server cannot speak this client's TLS: 1.3, P-256 (or the hybrid
 * beside it) and the two AES-GCM suites - and said so before its ServerHello
 * was accepted.
 *
 * <p>Its own type because it is the one handshake failure that means "try
 * the JDK's stack" rather than "something is wrong": a TLS 1.2 server, one
 * that asks for another key share, one that hangs up on the ClientHello.
 * Nothing about the server has been authenticated at that point, and nothing
 * secret has been sent, so the cause carries no certificate verdict - a
 * certificate the client refuses is never one of these.
 *
 * <p>The cause is what actually happened: the peer's alert, the alert this
 * client sent, or the connection ending.
 */
public final class TlsVersionRefused extends IOException {

    private static final long serialVersionUID = 1L;

    public TlsVersionRefused(IOException cause) {
        super("the server does not speak TLS 1.3 with P-256 - " + cause.getMessage(), cause);
    }
}
