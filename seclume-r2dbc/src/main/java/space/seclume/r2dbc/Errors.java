package space.seclume.r2dbc;

import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.SQLTransientException;

import io.r2dbc.spi.R2dbcBadGrammarException;
import io.r2dbc.spi.R2dbcDataIntegrityViolationException;
import io.r2dbc.spi.R2dbcException;
import io.r2dbc.spi.R2dbcNonTransientResourceException;
import io.r2dbc.spi.R2dbcPermissionDeniedException;
import io.r2dbc.spi.R2dbcRollbackException;
import io.r2dbc.spi.R2dbcTimeoutException;
import io.r2dbc.spi.R2dbcTransientResourceException;

/**
 * JDBC's failures as R2DBC's, by SQLSTATE class - what Spring's exception
 * translation and an application's error handling look at. The message,
 * the state and the vendor code go along unchanged.
 */
final class Errors {

    private Errors() {
    }

    static Throwable translate(Throwable failure) {
        if (!(failure instanceof SQLException sql)) {
            return failure;
        }
        String message = sql.getMessage();
        String state = sql.getSQLState();
        int code = sql.getErrorCode();
        if (sql instanceof SQLTimeoutException
                || "57014".equals(state)) {                     // query canceled
            return new R2dbcTimeoutException(message, state, code, sql);
        }
        String family = state == null || state.length() < 2 ? "" : state.substring(0, 2);
        R2dbcException translated = switch (family) {
            case "23" -> new R2dbcDataIntegrityViolationException(message, state, code, sql);
            // 42 is the standard's; S0 is the ODBC class SQL Server still
            // reports for a missing table, column or procedure.
            case "42", "S0" -> new R2dbcBadGrammarException(message, state, code, sql);
            case "28" -> new R2dbcPermissionDeniedException(message, state, code, sql);
            case "40" -> new R2dbcRollbackException(message, state, code, sql);
            case "08" -> sql instanceof SQLTransientException
                    ? new R2dbcTransientResourceException(message, state, code, sql)
                    : new R2dbcNonTransientResourceException(message, state, code, sql);
            default -> sql instanceof SQLTransientException
                    ? new R2dbcTransientResourceException(message, state, code, sql)
                    : new R2dbcNonTransientResourceException(message, state, code, sql);
        };
        return translated;
    }
}
