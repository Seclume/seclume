package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import space.seclume.logging.SecretMasker;

/**
 * seclume.logging.redact=true: the application's own secrets - here one named
 * by seclume.heapdump.secrets - are masked in what goes to the log, and no
 * longer once the context is closed; off unless asked for.
 */
class LogRedactionTest {

    @TempDir
    Path directory;

    private AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeOomDumpAutoConfiguration.class,
                SeclumeLogRedactionAutoConfiguration.class);
        context.refresh();
        return context;
    }

    @Test
    void theApplicationsSecretsAreMaskedInWhatIsLogged() throws Exception {
        Path key = Files.writeString(directory.resolve("api-key"), "an-api-key-0123456789");
        Map<String, Object> properties = new HashMap<>();
        properties.put("seclume.heapdump.secrets.api.provider", "file");
        properties.put("seclume.heapdump.secrets.api.path", key.toString());
        properties.put("seclume.heapdump.oom.folder", directory.toString());
        try (AnnotationConfigApplicationContext off = context(properties)) {
            assertTrue(off.getBeansOfType(
                    SeclumeLogRedactionAutoConfiguration.LogRedaction.class).isEmpty());
        }
        properties.put("seclume.logging.redact", "true");
        try (AnnotationConfigApplicationContext on = context(properties)) {
            assertEquals("calling with [redacted:seclume.heapdump.secrets.api]",
                    SecretMasker.maskInstalled("calling with an-api-key-0123456789"));
            // Two forms per secret - UTF-16 and Base64. The data sources other
            // tests in this JVM made are registered too, for as long as the
            // garbage collector leaves them, so the count is two or more.
            int forms = on.getBean(SeclumeLogRedactionAutoConfiguration.LogRedaction.class)
                    .masker().forms();
            assertTrue(forms >= 2 && forms % 2 == 0, "two per secret, the configured one among them: " + forms);
            assertTrue(on.getBean(RedactionSecrets.class).labels().contains("seclume.heapdump.secrets.api"),
                    on.getBean(RedactionSecrets.class).labels().toString());
        }
        assertEquals("calling with an-api-key-0123456789",
                SecretMasker.maskInstalled("calling with an-api-key-0123456789"));

        properties.put("seclume.logging.refresh-interval", "0s");
        Exception refused = assertThrows(Exception.class, () -> context(properties).close());
        Throwable root = refused;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        assertTrue(root.getMessage().contains("refresh-interval"), root.getMessage());
    }
}
