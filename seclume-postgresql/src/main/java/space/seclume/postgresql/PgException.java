package space.seclume.postgresql;

import java.sql.SQLException;

/**
 * An error the server sent.
 *
 * <p>Carries the SQLState along, because Spring builds its
 * {@code SQLExceptionTranslator} on exactly that - an exception without a
 * SQLState arrives there as "something went wrong".
 *
 * <p>What the server sends is protocol text and may go into the message. What
 * the client sent may not: an error message carrying the parameter that was
 * sent would be one way for a password to end up in the log.
 */
public class PgException extends SQLException {

    private static final long serialVersionUID = 1L;

    private final String severity;
    private final String detail;

    public PgException(String message, String sqlState, String severity, String detail) {
        super(message, sqlState);
        this.severity = severity;
        this.detail = detail;
    }

    public String severity() {
        return severity;
    }

    public String detail() {
        return detail;
    }
}
