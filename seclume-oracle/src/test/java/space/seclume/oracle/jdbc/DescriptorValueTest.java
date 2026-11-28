package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.DriverManager;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * Service and host go into {@code (DESCRIPTION=...)} as they are: a
 * parenthesis or an equals sign in either added entries of its own - a
 * SERVICE_NAME or INSTANCE_NAME the application never chose. Refused before
 * anything is dialled, as an SQLException 08001 out of the driver.
 */
class DescriptorValueTest {

    private static final String TAIL = "?user=app&provider=file&path=/run/secrets/decoy";

    @Test
    void aServiceThatClosesTheDescriptorIsRefused() {
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection("jdbc:seclume:oracle://db.example.com:1521/"
                        + "FREEPDB1)(SERVICE_NAME=OTHER" + TAIL).close());
        assertEquals("08001", refused.getSQLState(), refused.getMessage());
        // Refused for what it is - not for a host that cannot be reached.
        org.junit.jupiter.api.Assertions.assertTrue(
                refused.getMessage().contains("service name"), refused.getMessage());
    }

    @Test
    void aHostThatClosesTheDescriptorIsRefused() {
        SQLException refused = assertThrows(SQLException.class, () -> OraUrl.settings(
                "jdbc:seclume:oracle://db)(PORT=1:1521/FREEPDB1" + TAIL, null));
        org.junit.jupiter.api.Assertions.assertTrue(
                refused.getMessage().contains("not a host name"), refused.getMessage());
    }

    /** The same through the DataSource's setter: an SQLException 08001, not an IllegalArgumentException. */
    @Test
    void aServiceSetOnTheDataSourceIsRefusedAsAnSqlException() {
        OraDataSource source = new OraDataSource();
        source.setHost("db.example.com");
        source.setPort(1521);
        source.setService("FREEPDB1)(SERVICE_NAME=OTHER");
        source.setUser("app");
        source.setSecretProvider(new space.seclume.tck.StaticSecretProvider("decoy-password"));
        SQLException refused = assertThrows(SQLException.class, () -> source.getConnection().close());
        assertEquals("08001", refused.getSQLState(), refused.getMessage());
        org.junit.jupiter.api.Assertions.assertTrue(
                refused.getMessage().contains("service name"), refused.getMessage());
    }

    @Test
    void ordinaryNamesStillWork() {
        for (String target : new String[] {"db.example.com:1521/FREEPDB1",
                "orcl.example.com:1521/orcl.example.com", "[::1]:1521/XE"}) {
            assertDoesNotThrow(() -> OraUrl.settings("jdbc:seclume:oracle://" + target + TAIL,
                    null), target);
        }
    }
}
