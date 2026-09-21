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
 * <p><b>Why there is a choice at all.</b> {@link #JSSE} is what every JDBC
 * driver does and what every server in the world has been tested against; it
 * resumes sessions, speaks TLS 1.2, and takes whatever key exchange the JDK
 * offers. {@link #SECLUME} gives up all of that for two things JSSE cannot
 * offer at any price: the traffic secrets never become Java objects, and the
 * encryption state can be frozen and taken up on another machine. Only a
 * caller knows which of those matters more for their connection, so only a
 * caller decides - and the safe, boring one is the default.
 */
public enum TlsStack {

    /** The JDK's {@code SSLEngine}. The default, and what everybody else does. */
    JSSE,

    /**
     * This project's own TLS 1.3 client.
     *
     * <p>One key exchange group (P-256), two cipher suites, no resumption and
     * no TLS 1.2. A server that needs any of those belongs on {@link #JSSE},
     * and says so with a handshake failure rather than a silent downgrade.
     */
    SECLUME;

    /** Parses the value of a URL option or a property. */
    public static TlsStack of(String value) throws SQLException {
        if (value == null || value.isEmpty()) {
            return JSSE;
        }
        return switch (value.toLowerCase(Locale.ROOT).replace('_', '-')) {
            case "jsse", "jdk", "default" -> JSSE;
            case "seclume", "own" -> SECLUME;
            default -> throw new SQLException("unknown tls stack \"" + value
                    + "\" - use jsse or seclume", "08001");
        };
    }
}
