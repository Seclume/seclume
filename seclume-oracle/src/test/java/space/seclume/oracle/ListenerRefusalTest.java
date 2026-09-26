package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.SQLTransientConnectionException;

import org.junit.jupiter.api.Test;

/**
 * A listener's REFUSE says why, and the driver passes it on: the ORA number
 * as message and error code, busy as transient, the rest as final.
 */
class ListenerRefusalTest {

    @Test
    void aBusyListenerIsTransientAndNamed() {
        SQLException busy = OracleSession.refused(
                "(DESCRIPTION=(TMP=)(VSNNUM=385875968)(ERR=12516)(ERROR_STACK=(ERROR=(CODE=12516)"
                        + "(EMFI=4))))");
        assertInstanceOf(SQLTransientConnectionException.class, busy);
        assertEquals(12516, busy.getErrorCode());
        assertEquals("08001", busy.getSQLState());
        assertTrue(busy.getMessage().startsWith("ORA-12516"), busy.getMessage());
    }

    @Test
    void anUnknownServiceIsFinal() {
        SQLException unknown = OracleSession.refused("(DESCRIPTION=(ERR=12514)(VSNNUM=0))");
        assertInstanceOf(SQLNonTransientConnectionException.class, unknown);
        assertEquals(12514, unknown.getErrorCode());
        assertTrue(unknown.getMessage().contains("does not know this service"),
                unknown.getMessage());
    }

    @Test
    void aRefusalWithoutANumberStillSaysWhatItGot() {
        SQLException bare = OracleSession.refused("something else");
        assertInstanceOf(SQLNonTransientConnectionException.class, bare);
        assertTrue(bare.getMessage().contains("something else"), bare.getMessage());
        assertTrue(OracleSession.refused("").getMessage().endsWith("refused the connection"));
    }
}
