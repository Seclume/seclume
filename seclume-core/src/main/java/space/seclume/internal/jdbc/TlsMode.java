package space.seclume.internal.jdbc;

import java.sql.SQLException;
import java.util.Locale;

/**
 * How much encryption a connection asks for.
 *
 * <p>The names follow what the ecosystem already says, because a driver that
 * invents its own words for this makes people guess at exactly the setting
 * they must not guess at.
 *
 * <p>The important distinction is not on/off but **encrypted** against
 * **authenticated**: {@link #REQUIRE} stops somebody listening on the wire,
 * {@link #VERIFY_FULL} also stops somebody standing in the middle of it. A
 * driver that offers only the first and calls it „secure" is lying by omission,
 * so both are here and the difference is written down.
 */
public enum TlsMode {

    /** No TLS at all. The payload travels in the clear. */
    OFF,

    /**
     * Use TLS if the server offers it, carry on in the clear if it does not.
     * The certificate is not checked, so this protects against a listener and
     * not against a man in the middle.
     */
    PREFER,

    /** TLS or no connection — still without checking the certificate. */
    REQUIRE,

    /**
     * TLS, with the certificate checked against the trust store <b>and</b>
     * against the host that was dialled. The only mode that authenticates the
     * server.
     */
    VERIFY_FULL;

    /** Whether the certificate and the host name are checked. */
    public boolean verifies() {
        return this == VERIFY_FULL;
    }

    /** Whether a server that offers no TLS is an error. */
    public boolean demands() {
        return this == REQUIRE || this == VERIFY_FULL;
    }

    /** Parses the value of a URL option or a property. */
    public static TlsMode of(String value) throws SQLException {
        if (value == null || value.isEmpty()) {
            return PREFER;
        }
        return switch (value.toLowerCase(Locale.ROOT).replace('_', '-')) {
            case "off", "false", "disable", "disabled" -> OFF;
            case "prefer", "true", "allow" -> PREFER;
            case "require" -> REQUIRE;
            case "verify-full", "verify-ca", "full" -> VERIFY_FULL;
            default -> throw new SQLException("unknown tls mode \"" + value
                    + "\" - use off, prefer, require or verify-full", "08001");
        };
    }
}
