package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.reflect.Method;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * {@code /actuator/cbom}: there with the actuator, named {@code cbom}, served
 * as CycloneDX's media type, the application's name in it - and a secret the
 * application read is in it by its provider only.
 *
 * <p>Isolated: the inventory is the process's.
 */
@Isolated
class CbomEndpointTest {

    private static final String CANARY = "zl-cbom-endpoint-canary-41e7";

    @Test
    void theEndpointServesTheInventoryAsCycloneDx() throws Exception {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test",
                Map.of("spring.application.name", "orders")));
        context.register(SeclumeCbomAutoConfiguration.class);
        context.refresh();
        try (context) {
            SeclumeCbomEndpoint endpoint = context.getBean(SeclumeCbomEndpoint.class);
            assertEquals("cbom", SeclumeCbomEndpoint.class.getAnnotation(Endpoint.class).id());
            Method read = SeclumeCbomEndpoint.class.getMethod("cbom");
            assertEquals("application/vnd.cyclonedx+json",
                    read.getAnnotation(ReadOperation.class).produces()[0]);

            SecretProvider provider = new SecretProvider() {
                @Override
                public int writeSecret(MemorySegment target) {
                    byte[] bytes = CANARY.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                    MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                    return bytes.length;
                }

                @Override
                public int maxSecretLength() {
                    return 64;
                }
            };
            SecretScope.fromProvider(provider).close();

            String cbom = endpoint.cbom();
            assertTrue(cbom.contains("\"specVersion\": \"1.6\""), cbom);
            assertTrue(cbom.contains("{\"type\": \"application\", \"name\": \"orders\"}"), cbom);
            assertTrue(cbom.contains("\"callback secret"), cbom);
            assertFalse(cbom.contains(CANARY), "a secret's value is in the CBOM");
        }
    }
}
