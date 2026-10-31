package space.seclume.quarkus.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

/** A field encryption key that cannot be read stops the start, with the reason. */
class FieldKeyRefusedTest {

    @RegisterExtension
    static final QuarkusExtensionTest APP = new QuarkusExtensionTest()
            .overrideConfigKey("quarkus.datasource.devservices.enabled", "false")
            .overrideConfigKey("seclume.field-encryption.keys.1.provider", "file")
            .overrideConfigKey("seclume.field-encryption.keys.1.path",
                    "/nonexistent/seclume-field-key")
            .assertException(thrown -> {
                StringBuilder chain = new StringBuilder();
                for (Throwable t = thrown; t != null; t = t.getCause()) {
                    chain.append(t).append('\n');
                }
                assertTrue(chain.toString().contains("seclume-field-key"), chain.toString());
            });

    @Test
    void theStartFails() {
        fail("the application should not have started");
    }
}
