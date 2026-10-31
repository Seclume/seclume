package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import space.seclume.audit.AccessLog;
import space.seclume.audit.AccessLogVerifier;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The access log from {@code application.properties}: opened and installed
 * with the context, a read recorded, closed with it - and nothing at all
 * without {@code seclume.audit.file}.
 *
 * <p>Isolated: the installed log is the process's.
 */
@Isolated
class AccessLogAutoConfigurationTest {

    @TempDir
    Path directory;

    private static AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test",
                new LinkedHashMap<>(properties)));
        context.register(SeclumeAccessLogAutoConfiguration.class);
        context.refresh();
        return context;
    }

    @Test
    void theLogLivesAndDiesWithTheContext() throws Exception {
        Path file = directory.resolve("access.jsonl");
        try (AnnotationConfigApplicationContext context = context(Map.of("seclume.audit.file", file.toString()))) {
            AccessLog log = context.getBean(SeclumeAccessLogAutoConfiguration.SeclumeAccessLog.class).log();
            assertSame(log, AccessLog.installed());
            SecretProvider provider = new SecretProvider() {
                @Override
                public int writeSecret(MemorySegment target) {
                    target.set(ValueLayout.JAVA_BYTE, 0, (byte) 'x');
                    return 1;
                }

                @Override
                public int maxSecretLength() {
                    return 8;
                }

                @Override
                public String toString() {
                    return "the test's provider";
                }
            };
            try (SecretScope ignored = SecretScope.fromProvider(provider)) {
                assertEquals(1, ignored.length());
            }
        }
        assertNull(AccessLog.installed());
        String text = Files.readString(file);
        assertTrue(text.contains("\"source\":\"the test's provider\""), text);
        assertTrue(AccessLogVerifier.verify(file, null).holds());
    }

    @Test
    void withoutAFileThereIsNoLog() {
        try (AnnotationConfigApplicationContext context = context(Map.of())) {
            assertFalse(context.getBeanNamesForType(SeclumeAccessLogAutoConfiguration.SeclumeAccessLog.class)
                    .length > 0);
            assertNull(AccessLog.installed());
        }
    }
}
