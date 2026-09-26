package space.seclume.tls;

import java.io.IOException;

/**
 * <b>We</b> are stopping, and this is the alert we sent the peer to say why.
 *
 * <p>The mirror image of {@link TlsAlertException}, which is the peer's
 * reason. Kept apart on purpose: "the server refused us" and "we refused the
 * server" send whoever reads the log to opposite ends of the connection.
 *
 * <p>The alert is a fatal one from RFC 8446 section 6 - typically
 * {@code unexpected_message} for a message in the wrong place and
 * {@code illegal_parameter} for a field with a value the protocol does not
 * allow. Sending it is best effort; the connection is closed either way.
 */
public final class TlsProtocolException extends IOException {

    private static final long serialVersionUID = 1L;

    private final int alert;

    public TlsProtocolException(int alert, String message) {
        super(message + " (" + TlsAlertException.name(alert) + ")");
        this.alert = alert;
    }

    /** The alert description sent to the peer, RFC 8446 section 6. */
    public int alert() {
        return alert;
    }
}
