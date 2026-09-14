package space.seclume.mysql;

import java.sql.SQLException;

/**
 * An error the server sent.
 *
 * <p>MySQL names an error number of its own and - since protocol 4.1 - a
 * SQLState on top. Both are passed through: the number is what one looks up in
 * the MySQL documentation, the SQLState what portable code checks.
 */
public final class MyException extends SQLException {

    private static final long serialVersionUID = 1L;

    private final int errorCode;

    public MyException(String message, String sqlState, int errorCode) {
        super(message, sqlState, errorCode);
        this.errorCode = errorCode;
    }

    /** The MySQL error number, 1045 for "Access denied" say. */
    public int errorNumber() {
        return errorCode;
    }
}
