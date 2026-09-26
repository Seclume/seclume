package space.seclume.quarkus.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.test.QuarkusExtensionTest;

/** A seclume datasource with {@code quarkus.datasource.password} does not build. */
class PasswordRefusedTest {

    @RegisterExtension
    static final QuarkusExtensionTest APP = new QuarkusExtensionTest()
            .overrideConfigKey("quarkus.datasource.db-kind", "seclume-postgresql")
            .overrideConfigKey("quarkus.datasource.devservices.enabled", "false")
            .overrideConfigKey("quarkus.datasource.jdbc.url",
                    "jdbc:seclume:postgresql://127.0.0.1:5432/app?user=app")
            .overrideConfigKey("quarkus.datasource.password", "not-a-real-password")
            .assertException(thrown -> {
                Throwable cause = thrown;
                while (cause != null && !(cause instanceof ConfigurationException)) {
                    cause = cause.getCause();
                }
                assertTrue(cause != null, "expected a ConfigurationException, got " + thrown);
                assertTrue(cause.getMessage().contains("quarkus.datasource.password"),
                        cause.getMessage());
            });

    @Test
    void theBuildFails() {
        fail("the application should not have started");
    }
}
