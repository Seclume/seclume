package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.core.LoggerContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

/**
 * seclume.logging.redact=true with Log4j 2 as the application's logging: the
 * starter installs the masker, a log4j2.xml with %redact{...} masks the
 * application's secret in message and stack trace - and once the context is
 * closed the masker is gone and lines are written as they are.
 *
 * <p>Log4j's own context, made here, not the one LogManager would pick: other
 * logging on the test class path must not decide which is used. Isolated: the
 * installed masker is the JVM's.
 */
@Isolated
class Log4j2RedactionStarterTest {

    private static final String SECRET = "an-api-key-0123456789";

    @TempDir
    Path directory;

    private LoggerContext log4j(Path log) throws Exception {
        Path xml = Files.writeString(directory.resolve("log4j2.xml"), """
                <Configuration status="warn">
                  <Appenders>
                    <File name="file" fileName="%s" immediateFlush="true">
                      <PatternLayout pattern="%s"/>
                    </File>
                  </Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="file"/></Root></Loggers>
                </Configuration>
                """.formatted(log, "%level %redact{%msg%n%throwable}"));
        LoggerContext context = new LoggerContext("starter-redaction", null, xml.toUri());
        context.start();
        return context;
    }

    private AnnotationConfigApplicationContext spring(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeOomDumpAutoConfiguration.class, SeclumeLogRedactionAutoConfiguration.class);
        context.refresh();
        return context;
    }

    @Test
    void theStartersMaskerMasksLog4jLinesWhileTheContextRuns() throws Exception {
        Path key = Files.writeString(directory.resolve("api-key"), SECRET);
        Map<String, Object> properties = new HashMap<>();
        properties.put("seclume.heapdump.secrets.api.provider", "file");
        properties.put("seclume.heapdump.secrets.api.path", key.toString());
        properties.put("seclume.heapdump.oom.folder", directory.toString());
        properties.put("seclume.logging.redact", "true");

        Path log = directory.resolve("app.log");
        LoggerContext log4j = log4j(log);
        try {
            try (AnnotationConfigApplicationContext _ = spring(properties)) {
                log4j.getLogger("app").info("calling the API with {}", SECRET);
                log4j.getLogger("app").error("the call failed", new IllegalStateException(
                        "401 for key " + SECRET));
            }
            log4j.getLogger("app").info("after the context: {}", SECRET);
        } finally {
            log4j.stop();
        }
        String written = Files.readString(log, StandardCharsets.UTF_8);
        String during = written.substring(0, written.indexOf("after the context"));
        assertFalse(during.contains(SECRET), written);
        assertTrue(during.contains("INFO calling the API with [redacted:seclume.heapdump.secrets.api]"), written);
        assertTrue(during.contains("401 for key [redacted:seclume.heapdump.secrets.api]"), written);
        assertTrue(written.contains("after the context: " + SECRET),
                "the masker goes with the context; nothing stays installed: " + written);
    }
}
