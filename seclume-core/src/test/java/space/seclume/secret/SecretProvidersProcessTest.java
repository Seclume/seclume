package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.JdbcUrl;

/**
 * {@code provider=process} starts a program, and a JDBC URL or its properties
 * are what some applications take from their users: a URL that named a
 * command ran it. It is refused unless the JVM was started with
 * {@code -Dseclume.secret.process.allowed=true}.
 */
@Isolated
class SecretProvidersProcessTest {

    private static final String PREFIX = "jdbc:seclume:postgresql:";

    @TempDir
    Path directory;

    private String touch() {
        return "touch%20" + directory.resolve("marker").toString().replace('\\', '/');
    }

    @Test
    void aProcessProviderInAUrlIsRefusedWithoutTheSwitch() {
        JdbcUrl.Parsed parsed = JdbcUrl.parse(PREFIX + "//127.0.0.1:5432/db?provider=process"
                + "&command=" + touch(), null, PREFIX, 5432);
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SecretProviders.of(parsed.options()));
        assertTrue(refused.getMessage().contains("seclume.secret.process.allowed"),
                refused.getMessage());
        assertFalse(Files.exists(directory.resolve("marker")), "the command ran");
    }

    @Test
    void aProcessProviderInPropertiesIsRefusedWithoutTheSwitch() {
        Properties properties = new Properties();
        properties.setProperty("provider", "process");
        properties.setProperty("command", touch().replace("%20", " "));
        JdbcUrl.Parsed parsed = JdbcUrl.parse(PREFIX + "//127.0.0.1:5432/db", properties,
                PREFIX, 5432);
        assertThrows(IllegalArgumentException.class, () -> SecretProviders.of(parsed.options()));
        assertFalse(Files.exists(directory.resolve("marker")), "the command ran");
    }

    @Test
    void theSwitchAllowsIt() {
        String before = System.getProperty("seclume.secret.process.allowed");
        System.setProperty("seclume.secret.process.allowed", "true");
        try {
            JdbcUrl.Parsed parsed = JdbcUrl.parse(PREFIX + "//127.0.0.1:5432/db?provider=process"
                    + "&command=printf%20decoy", null, PREFIX, 5432);
            assertInstanceOf(ProcessSecretProvider.class, SecretProviders.of(parsed.options()),
                    "the opt-in");
        } finally {
            if (before == null) {
                System.clearProperty("seclume.secret.process.allowed");
            } else {
                System.setProperty("seclume.secret.process.allowed", before);
            }
        }
    }
}
