package space.seclume.sqlserver.tds;

import java.sql.SQLException;
import java.util.Locale;

/**
 * Where TLS sits relative to TDS, which is the only thing the two versions
 * disagree about here.
 *
 * <p>This looks like a protocol version and is really a decision about
 * layering, so it is worth writing down which way round each one is.
 *
 * <p><b>7.4</b> negotiates in the clear and then puts the TLS handshake
 * <em>inside</em> {@code PRELOGIN} packets; once the handshake is done the
 * nesting inverts and the TDS packets travel inside TLS records. That shape
 * is TLS 1.2 by construction - TLS 1.3 moves handshake messages past the
 * point where the inversion would have to happen - so it can never use a
 * TLS 1.3 client, and therefore never seclume's own stack, and therefore
 * never a client certificate whose key stays off the heap.
 *
 * <p><b>8.0</b> puts TLS around the whole connection from the first byte.
 * Nothing is negotiated in the clear, not even the pre-login. The server
 * tells a TDS 8.0 client from anything else arriving on port 1433 by the
 * ALPN protocol name {@code tds/8.0}, which is why the handshake has to
 * offer it and why a server that does not select it is refused rather than
 * talked to.
 *
 * <p>The default stays 7.4. It works against every SQL Server in service,
 * 8.0 needs 2022 or later, and a driver that silently required a version of
 * the server would be a worse neighbour than one that asks.
 */
public enum TdsVersion {

    /** TLS inside the pre-login, then TDS inside TLS. The default. */
    TDS_7_4,

    /**
     * TLS around everything, from the first byte - Microsoft calls it strict
     * encryption. Needs SQL Server 2022 or later.
     */
    TDS_8_0;

    /** The protocol name TDS 8.0 has to offer in the TLS handshake. */
    public static final String ALPN = "tds/8.0";

    /** Whether TLS wraps the connection rather than being nested in it. */
    public boolean wrapsTheConnection() {
        return this == TDS_8_0;
    }

    /**
     * Parses the value of a URL option or a property.
     *
     * <p>{@code strict} is accepted because that is what Microsoft's driver
     * calls the same thing, and somebody moving across should not have to
     * learn a second word for it.
     */
    public static TdsVersion of(String value) throws SQLException {
        if (value == null || value.isEmpty()) {
            return TDS_7_4;
        }
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "7.4", "74", "default" -> TDS_7_4;
            case "8.0", "8", "80", "strict" -> TDS_8_0;
            default -> throw new SQLException("unknown TDS version \"" + value
                    + "\" - use 7.4 or 8.0 (also spelled strict)", "08001");
        };
    }
}
