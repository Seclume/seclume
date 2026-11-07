package space.seclume.quarkus.deployment;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.test.QuarkusExtensionTest;

/**
 * A password that only the running application sees - here a runtime
 * property spelled as the environment variable a container would set - stops
 * the start. The build never saw it: the datasource password is a runtime
 * property, and the build's check was the only one.
 */
class RuntimePasswordRefusedTest {

    @RegisterExtension
    static final QuarkusExtensionTest APP = new QuarkusExtensionTest()
            .overrideConfigKey("quarkus.datasource.db-kind", "seclume-postgresql")
            .overrideConfigKey("quarkus.datasource.devservices.enabled", "false")
            .overrideConfigKey("quarkus.datasource.jdbc.url",
                    "jdbc:seclume:postgresql://127.0.0.1:5432/app?user=app")
            .overrideRuntimeConfigKey("QUARKUS_DATASOURCE_PASSWORD", "zl-quarkus-canary")
            .assertException(thrown -> {
                Throwable cause = thrown;
                while (cause != null && !(cause instanceof ConfigurationException)) {
                    cause = cause.getCause();
                }
                assertTrue(cause != null, "expected a ConfigurationException, got " + thrown);
                assertTrue(cause.getMessage().contains("QUARKUS_DATASOURCE_PASSWORD"),
                        cause.getMessage());
                assertFalse(cause.getMessage().contains("zl-quarkus-canary"), cause.getMessage());
            });

    @Test
    void theStartFails() {
        fail("the application should not have started");
    }
}
