package space.seclume.internal.jdbc;

import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.SQLInvalidAuthorizationSpecException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTransactionRollbackException;

/**
 * A server's error as the {@code SQLException} subclass JDBC 4 names for its
 * SQLState class.
 *
 * <p>JDBC gives each family of states a type - {@code 23} a constraint
 * violation, {@code 42} a syntax or access error, {@code 40} a rolled-back
 * transaction - so that an application can write
 * {@code catch (SQLIntegrityConstraintViolationException e)} instead of
 * comparing strings. ojdbc and Connector/J raise those types, and code written
 * against them catches nothing when a driver throws the plain base class with
 * the same state. This is the one place the choice is made, by the class of
 * the state and nothing else, so every driver makes it alike.
 */
public final class SqlErrors {

    private SqlErrors() {
    }

    /**
     * The exception for this state: the JDBC 4 subclass of its class where
     * there is one, the plain {@code SQLException} otherwise.
     *
     * @param message what the caller reads
     * @param state   the five-character SQLState, or {@code null}
     * @param code    the vendor's error number
     */
    public static SQLException of(String message, String state, int code) {
        if (state == null || state.length() < 2) {
            return new SQLException(message, state, code);
        }
        return switch (state.substring(0, 2)) {
            case "22" -> new SQLDataException(message, state, code);
            case "23" -> new SQLIntegrityConstraintViolationException(message, state, code);
            case "28" -> new SQLInvalidAuthorizationSpecException(message, state, code);
            case "40" -> new SQLTransactionRollbackException(message, state, code);
            case "42" -> new SQLSyntaxErrorException(message, state, code);
            case "0A" -> new SQLFeatureNotSupportedException(message, state, code);
            case "08" -> new SQLNonTransientConnectionException(message, state, code);
            default -> new SQLException(message, state, code);
        };
    }
}
