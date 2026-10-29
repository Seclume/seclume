package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

/**
 * The dumps a JVM leaves on an {@code OutOfMemoryError}: where they are looked
 * for, and a real one of this JVM, with a token in it, redacted where it lies.
 */
@Timeout(300)
class OomDumpRedactionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** What the dump has to lose. */
    static String token;

    private static String alnum(int length) {
        String letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            out.append(letters.charAt(RANDOM.nextInt(letters.length())));
        }
        return out.toString();
    }

    @Test
    void theFolderIsWhereTheJvmWritesItsDumps(@TempDir Path directory) {
        assertNull(OomDumpRedaction.folder(null,
                new OomDumpRedaction.VmOptions(false, directory.toString())),
                "a JVM that writes no dumps has nothing to watch");
        assertEquals(directory, OomDumpRedaction.folder(null,
                new OomDumpRedaction.VmOptions(true, directory.toString())));
        assertEquals(directory, OomDumpRedaction.folder(null,
                new OomDumpRedaction.VmOptions(true, directory.resolve("app.hprof").toString())));
        assertEquals(Path.of(System.getProperty("user.dir")), OomDumpRedaction.folder(null,
                new OomDumpRedaction.VmOptions(true, "")));
        assertEquals(Path.of("/elsewhere"), OomDumpRedaction.folder("/elsewhere",
                new OomDumpRedaction.VmOptions(false, "")));
    }

    @Test
    void aDumpOfThisJvmIsRedactedWhereItLies(@TempDir Path folder) throws Exception {
        String body = alnum(36);
        token = "ghp_" + body;
        Path dump = folder.resolve("java_pid1.hprof");
        ManagementFactory.getPlatformMXBean(com.sun.management.HotSpotDiagnosticMXBean.class)
                .dumpHeap(dump.toString(), true);
        try (OomDumpRedaction redaction = OomDumpRedaction.start(folder, Set.of(),
                Duration.ofHours(1))) {
            assertEquals(0, redaction.checkNow(), "taken at the first look");
            assertEquals(1, redaction.checkNow());
        }
        List<Path> left;
        try (Stream<Path> files = Files.list(folder)) {
            left = files.toList();
        }
        assertEquals(1, left.size(), "the original or a partial copy is still there: " + left);
        assertTrue(left.get(0).getFileName().toString().endsWith(".redacted.hprof"));
        assertFalse(contains(left.get(0), body.getBytes(StandardCharsets.US_ASCII)),
                "the token is in the redacted dump");
        assertTrue(token.endsWith(body));
    }

    @Test
    void onByDefaultOffWhenSaidAndAnUnknownDetectorStopsTheStart(@TempDir Path folder) {
        try (AnnotationConfigApplicationContext context = context(Map.of(
                "seclume.heapdump.oom.folder", folder.toString()))) {
            assertEquals(folder, context.getBean(OomDumpRedaction.class).folder());
        }
        try (AnnotationConfigApplicationContext context = context(Map.of(
                "seclume.heapdump.oom.folder", folder.toString(),
                "seclume.heapdump.oom.redact", "false"))) {
            assertTrue(context.getBeansOfType(OomDumpRedaction.class).isEmpty());
        }
        Exception refused = org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                () -> context(Map.of("seclume.heapdump.oom.folder", folder.toString(),
                        "seclume.heapdump.ignore", "jwts")).close());
        StringBuilder messages = new StringBuilder();
        for (Throwable t = refused; t != null; t = t.getCause()) {
            messages.append(t.getMessage());
        }
        assertTrue(messages.toString().contains("jwts"), messages.toString());
    }

    private static AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeOomDumpAutoConfiguration.class);
        context.refresh();
        return context;
    }

    private static boolean contains(Path file, byte[] pattern) throws IOException {
        byte[] window = new byte[(8 << 20) + pattern.length];
        try (InputStream in = Files.newInputStream(file)) {
            int kept = 0;
            while (true) {
                int n = in.readNBytes(window, kept, window.length - kept);
                int length = kept + n;
                outer:
                for (int i = 0; i + pattern.length <= length; i++) {
                    for (int j = 0; j < pattern.length; j++) {
                        if (window[i + j] != pattern[j]) {
                            continue outer;
                        }
                    }
                    return true;
                }
                if (n == 0 || length < window.length) {
                    return false;
                }
                kept = pattern.length - 1;
                System.arraycopy(window, length - kept, window, 0, kept);
            }
        }
    }
}
