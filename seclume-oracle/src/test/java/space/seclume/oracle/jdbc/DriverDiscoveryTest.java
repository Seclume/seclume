package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * That an application finds this driver at all - without a server.
 *
 * <p>Everything else here connects first, so the one step before connecting was
 * only ever proven when a database happened to be running: the file under
 * {@code META-INF/services} that tells the {@code ServiceLoader} our class name.
 * A rename, a typo, a resource that does not make it into the jar - each of them
 * leaves a driver that is perfectly correct and that nobody can reach, and an
 * ordinary build stays green.
 *
 * <p>So this asks the way an application asks: by URL, through the
 * {@code DriverManager}, without naming the class. Naming it would load it, its
 * static block would register it, and the service file could be empty for all
 * the test would notice.
 */
class DriverDiscoveryTest {

    private static final String SERVICE = "META-INF/services/java.sql.Driver";

    @Test
    void theDriverManagerFindsUsByUrl() throws SQLException {
        Driver driver = DriverManager.getDriver("jdbc:seclume:oracle:thin:@//host/db");
        assertNotNull(driver, "no driver for our own URL");
        assertEquals(registeredName(), driver.getClass().getName(),
                "the driver that answers is not the one " + SERVICE + " names");
    }

    /** And it keeps its hands off what is not its own. */
    @Test
    void aForeignUrlIsNotOurs() {
        assertThrows(SQLException.class,
                () -> DriverManager.getDriver("jdbc:seclume:postgresql://host/db"),
                "we answered a URL that belongs to somebody else");
    }

    /** The class name as it actually ships, read from the resource. */
    private static String registeredName() {
        try (InputStream service =
                     DriverDiscoveryTest.class.getClassLoader().getResourceAsStream(SERVICE)) {
            assertNotNull(service, SERVICE + " is not on the classpath - nothing finds this driver");
            return new String(service.readAllBytes(), StandardCharsets.UTF_8).strip();
        } catch (IOException e) {
            throw new AssertionError("cannot read " + SERVICE, e);
        }
    }
}
