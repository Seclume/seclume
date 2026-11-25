package space.seclume.internal.jdbc;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * What {@code Driver.connect} lets out: an SQLException, and nothing else.
 *
 * <p>A secret provider that fails - Vault not reachable, a file not there -
 * throws an unchecked exception out of its own code, and so does a URL that
 * cannot be read. Out of {@code DriverManager.getConnection} it passed every
 * caller that catches SQLException, which is every pool and every retry: the
 * failure was not counted, not retried, and took the thread with it.
 */
public final class ConnectFailures {

    /** Opens a connection; whatever it throws. */
    public interface Opening {
        Connection open() throws SQLException;
    }

    private ConnectFailures() {
    }

    /** The connection, or an SQLException - 08001 with the cause for anything unchecked. */
    public static Connection translated(Opening opening) throws SQLException {
        try {
            return opening.open();
        } catch (RuntimeException failure) {
            String message = failure.getMessage();
            throw new SQLException("the connection could not be set up: "
                    + (message == null ? failure.getClass().getSimpleName() : message),
                    "08001", failure);
        }
    }
}
