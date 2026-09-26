package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.SQLRecoverableException;
import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTimeoutException;
import java.sql.SQLTransactionRollbackException;
import java.sql.SQLTransientException;

import org.junit.jupiter.api.Test;

/**
 * Oracle's numbers as the state and type ojdbc raises, including the few that
 * need no running server to be told apart: the everyday ones are compared
 * against ojdbc itself by {@code ErrorCatalogTest}.
 */
class OraErrorMappingTest {

    private static void expect(int number, String state, Class<?> type) {
        SQLException error = OraStatement.error("ORA-" + number, number);
        assertEquals(state, error.getSQLState(), "ORA-" + number);
        assertSame(type, error.getClass(), "ORA-" + number);
        assertEquals(number, error.getErrorCode());
    }

    @Test
    void theStatesAndTypesOjdbcRaises() {
        expect(1, "23000", SQLIntegrityConstraintViolationException.class);
        expect(1400, "23000", SQLIntegrityConstraintViolationException.class);
        expect(942, "42000", SQLSyntaxErrorException.class);
        expect(1722, "42000", SQLSyntaxErrorException.class);
        expect(911, "22019", SQLSyntaxErrorException.class);
        expect(1476, "22012", SQLDataException.class);
        expect(1861, "22008", SQLDataException.class);
        expect(2091, "40000", SQLTransactionRollbackException.class);
        expect(1013, "72000", SQLTimeoutException.class);
        expect(3113, "08006", SQLRecoverableException.class);
        expect(100, "02000", SQLException.class);
        expect(6502, "65000", SQLException.class);
        expect(12899, "72000", SQLException.class);
        expect(20001, "72000", SQLException.class);
        expect(28000, "99999", SQLException.class);
    }

    @Test
    void whatRunningAgainCuresSaysSoInItsType() {
        expect(60, "61000", SQLTransactionRollbackException.class);
        expect(8177, "72000", SQLTransactionRollbackException.class);
        expect(4068, "72000", SQLTransientException.class);
    }
}
