package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.tck.StaticSecretProvider;

/**
 * A real Log4j 2, configured from XML with {@code %redact{...}}: the plugin is
 * found by Log4j's own index in the module's classes, what the inner pattern
 * writes - message, parameters, stack trace - is masked, the stack trace is
 * written once, and what is not a secret is left as it was.
 *
 * <p>Isolated: the installed masker is one for the whole JVM.
 */
@Isolated
class Log4j2RedactionTest {

    private static final String SECRET = "hunter2-but-longer";

    @TempDir
    Path directory;

    @AfterEach
    void uninstall() {
        SecretMasker.install(null);
    }

    private LoggerContext context(String name, Path log, String pattern) throws Exception {
        Path xml = directory.resolve(name + ".xml");
        Files.writeString(xml, """
                <Configuration status="warn">
                  <Appenders>
                    <File name="file" fileName="%s" immediateFlush="true">
                      <PatternLayout pattern="%s"/>
                    </File>
                  </Appenders>
                  <Loggers>
                    <Root level="info"><AppenderRef ref="file"/></Root>
                  </Loggers>
                </Configuration>
                """.formatted(log, pattern));
        return Configurator.initialize(name, null, xml.toUri());
    }

    private static SecretMasker masker() {
        SecretMasker masker = new SecretMasker(Map.of("db", new StaticSecretProvider(SECRET)));
        SecretMasker.install(masker);
        return masker;
    }

    @Test
    void messagesParametersAndStackTracesAreMaskedWhereTheyAreWritten() throws Exception {
        Path log = directory.resolve("app.log");
        LoggerContext context = context("masked", log, "%level %redact{%msg%n%throwable}");
        try (SecretMasker _ = masker()) {
            Logger logger = context.getLogger("app");
            logger.info("connecting with password {}", SECRET);
            logger.warn("the login failed", new IllegalStateException(
                    "jdbc:postgresql://db/app?password=" + SECRET + " refused"));
            logger.info("an ordinary line");
        } finally {
            Configurator.shutdown(context);
        }
        String written = Files.readString(log, StandardCharsets.UTF_8);
        assertTrue(written.contains("INFO "), "nothing was written: " + written);
        assertFalse(written.contains(SECRET), written);
        assertTrue(written.contains("INFO connecting with password [redacted:db]"), written);
        assertTrue(written.contains("password=[redacted:db] refused"), written);
        assertTrue(written.contains("INFO an ordinary line"), written);
        assertEquals(1, written.lines().filter(line -> line.startsWith("java.lang.IllegalStateException")).count(),
                "the stack trace is written once, inside %redact, and not again after the line:\n" + written);
    }

    @Test
    void theSecretsBase64IsMaskedAndTheRestOfThePatternStays() throws Exception {
        Path log = directory.resolve("base64.log");
        String encoded = Base64.getEncoder().encodeToString(SECRET.getBytes(StandardCharsets.UTF_8));
        LoggerContext context = context("base64", log, "[%logger] %redact{%msg}%n");
        try (SecretMasker _ = masker()) {
            context.getLogger("http").info("Authorization: Basic {}", encoded);
        } finally {
            Configurator.shutdown(context);
        }
        assertEquals("[http] Authorization: Basic [redacted:db]", Files.readString(log).strip());
    }

    @Test
    void withoutAMaskerTheLinesAreWrittenAsTheyAre() throws Exception {
        Path log = directory.resolve("plain.log");
        LoggerContext context = context("plain", log, "%redact{%msg}%n");
        try {
            context.getLogger("app").info("password {}", SECRET);
        } finally {
            Configurator.shutdown(context);
        }
        assertEquals("password " + SECRET, Files.readString(log).strip(),
                "no masker installed: %redact writes the line unchanged, and logging goes on");
    }
}
