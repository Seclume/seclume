package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import space.seclume.pool.SeclumePool;

/**
 * {@code pool.secret-watch-interval}: the password replaced in its file, and
 * the pool rotates by itself. No database needed - a rotation is decided
 * before anything connects.
 */
class SecretWatchAutoConfigurationTest {

    @TempDir
    Path directory;

    private AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeAutoConfiguration.class);
        context.refresh();
        return context;
    }

    private Map<String, Object> properties(Path password) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.datasources.main.url",
                "jdbc:seclume:postgresql://localhost:1/app");
        properties.put("seclume.datasources.main.username", "app");
        properties.put("seclume.datasources.main.secret.provider", "file");
        properties.put("seclume.datasources.main.secret.path",
                password.toString().replace('\\', '/'));
        return properties;
    }

    @Test
    void aRotatedPasswordRotatesThePool() throws Exception {
        Path password = directory.resolve("password");
        Files.writeString(password, "before");
        Map<String, Object> properties = properties(password);
        properties.put("seclume.datasources.main.pool.secret-watch-interval", "100ms");
        try (AnnotationConfigApplicationContext context = context(properties)) {
            SeclumePool pool = context.getBean(SeclumePool.class);
            assertEquals(0, pool.rotations());
            Path next = directory.resolve("next");
            Files.writeString(next, "after");
            Files.move(next, password, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            long deadline = System.nanoTime() + 10_000_000_000L;
            while (pool.rotations() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertEquals(1, pool.rotations(), "the pool did not rotate");
        }
    }

    @Test
    void withoutTheIntervalNothingIsWatched() throws Exception {
        Path password = directory.resolve("password");
        Files.writeString(password, "before");
        try (AnnotationConfigApplicationContext context = context(properties(password))) {
            SeclumePool pool = context.getBean(SeclumePool.class);
            Files.writeString(password, "after");
            Thread.sleep(300);
            assertTrue(pool.rotations() == 0, "rotated without being asked to watch");
        }
    }
}
