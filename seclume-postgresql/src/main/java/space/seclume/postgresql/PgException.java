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
        super(saySomething(message, sqlState, severity), sqlState);
        this.severity = severity;
        this.detail = detail;
    }

    /**
     * Never an empty message, because an empty one helps nobody.
     *
     * <p>The protocol makes the {@code M} field mandatory, so this is the
     * server being wrong - but "the server was wrong" is not something an
     * application can print, and what arrives in a log is
     * {@code getMessage()}. A {@code SQLException} whose message is blank
     * tells whoever reads the log that a statement failed and nothing
     * whatever about why, while the severity and the SQLState were sitting in
     * the same packet unused.
     *
     * <p>So the fields that did arrive are put where a reader will find them.
     * Found by the decoder fuzz sweep on 23.09.2026, on an ErrorResponse with
     * one byte changed.
     */
    private static String saySomething(String message, String sqlState, String severity) {
        if (message != null && !message.isBlank()) {
            return message;
        }
        StringBuilder made = new StringBuilder("the server refused the statement and sent no "
                + "message with it");
        if (severity != null && !severity.isBlank()) {
            made.append(" (").append(severity);
            made.append(sqlState == null || sqlState.isBlank() ? ")" : " " + sqlState + ")");
        } else if (sqlState != null && !sqlState.isBlank()) {
            made.append(" (").append(sqlState).append(')');
        }
        return made.toString();
    }

    public String severity() {
        return severity;
    }

    public String detail() {
        return detail;
    }
}
