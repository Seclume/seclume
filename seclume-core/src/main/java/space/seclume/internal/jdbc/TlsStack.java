package space.seclume.internal.jdbc;

import java.sql.SQLException;
import java.util.Locale;

/**
 * Which TLS implementation carries the connection.
 *
 * <p>Separate from {@link TlsMode} on purpose: the mode says how much
 * protection is asked for and is a decision about security, this says who
 * provides it and is a decision about capability. Mixing them into one option
 * would make {@code verify-full} and {@code seclume} look like alternatives,
 * which they are not - each stack offers every mode.
 *
 * <p><b>The default is this project's own stack</b>, for every server: TLS
 * 1.3, and for a server without it a small TLS 1.2 profile (ECDHE, AES-GCM,
 * the extended master secret). JSSE's AES-GCM copies the plaintext - the
 * password among it - through short-lived {@code byte[]} on the heap
 * (external audit SEC-04, 30.09.2026), so it is never chosen silently.
 * {@link #JSSE} remains for whoever asks for it by name: a server that speaks
 * neither profile - static RSA key exchange, CBC suites - and nothing newer.
 */
public enum TlsStack {

    /** The JDK's {@code SSLEngine} - what everybody else does. */
    JSSE,

    /**
     * This project's own TLS client: TLS 1.3, and the TLS 1.2 profile for a
     * server without it. No resumption. A server that needs anything else is
     * refused with a handshake failure rather than a change of stack.
     */
    SECLUME,

    /** The default, and the same as {@link #SECLUME}. */
    AUTO;

    /** Parses the value of a URL option or a property. */
    public static TlsStack of(String value) throws SQLException {
        if (value == null || value.isEmpty()) {
            return AUTO;
        }
        return switch (value.toLowerCase(Locale.ROOT).replace('_', '-')) {
            case "auto", "default" -> AUTO;
            case "jsse", "jdk" -> JSSE;
            case "seclume", "own" -> SECLUME;
            default -> throw new SQLException("unknown tls stack \"" + value
                    + "\" - use auto, seclume or jsse", "08001");
        };
    }
}
