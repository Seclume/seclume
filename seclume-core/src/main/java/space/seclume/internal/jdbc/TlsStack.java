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
 * encryption state can be written down and taken up again.
 *
 * <p><b>The default is {@link #AUTO}</b>: this project's own stack, and JSSE
 * only for a server that cannot speak it. JSSE's AES-GCM copies the
 * plaintext - the password among it - through short-lived {@code byte[]} on
 * the heap (external audit SEC-04, 30.09.2026), so the stack that keeps it
 * off the heap is the one to try first. See {@link TlsFallback}.
 */
public enum TlsStack {

    /** The JDK's {@code SSLEngine} - what everybody else does. */
    JSSE,

    /**
     * This project's own TLS 1.3 client.
     *
     * <p>One key exchange group (P-256), two cipher suites, no resumption and
     * no TLS 1.2. Chosen explicitly, a server that needs any of those is
     * refused with a handshake failure rather than a silent change of stack.
     */
    SECLUME,

    /**
     * The default: {@link #SECLUME}, and {@link #JSSE} for a server that
     * refuses it for want of TLS 1.3 - SQL Server before TDS 8.0, Oracle 19c,
     * MySQL 5.7. That change of stack is logged as a warning, once per server,
     * because from then on the password passes through the heap there.
     */
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
