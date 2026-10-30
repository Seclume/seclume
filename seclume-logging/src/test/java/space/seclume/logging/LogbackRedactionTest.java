package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.util.LogbackMDCAdapter;

import space.seclume.tck.StaticSecretProvider;

/**
 * A real Logback, configured from XML with the two conversion rules: the
 * message and the stack trace written to a file have the secret masked, and
 * what is not a secret is left as it was. Isolated: the installed masker is
 * one for the whole JVM.
 */
@Isolated
class LogbackRedactionTest {

    @TempDir
    Path directory;

    @Test
    void messagesAndStackTracesAreMaskedWhereTheyAreWritten() throws Exception {
        Path log = directory.resolve("app.log");
        String xml = """
                <configuration>
                  <conversionRule conversionWord="msg"
                      class="space.seclume.logging.logback.RedactingMessageConverter"/>
                  <conversionRule conversionWord="xEx"
                      class="space.seclume.logging.logback.RedactingThrowableConverter"/>
                  <appender name="FILE" class="ch.qos.logback.core.FileAppender">
                    <file>%s</file>
                    <encoder><pattern>%%level %%msg%%n%%xEx</pattern></encoder>
                  </appender>
                  <root level="INFO"><appender-ref ref="FILE"/></root>
                </configuration>
                """.formatted(log);
        // A context of its own, as SLF4J's provider would set it up: without an
        // MDC adapter every event fails to append, and the file stays empty.
        LoggerContext context = new LoggerContext();
        context.setMDCAdapter(new LogbackMDCAdapter());
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(context);
        configurator.doConfigure(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        try (SecretMasker masker = new SecretMasker(Map.of("db",
                new StaticSecretProvider("hunter2-but-longer")))) {
            SecretMasker.install(masker);
            Logger logger = context.getLogger("app");
            logger.info("connecting with password {}", "hunter2-but-longer");
            logger.warn("the login failed", new IllegalStateException(
                    "jdbc:postgresql://db/app?password=hunter2-but-longer refused"));
            logger.info("an ordinary line");
            context.stop();
        }
        String written = Files.readString(log);
        assertTrue(written.contains("INFO "), "nothing was written: " + written);
        assertFalse(written.contains("hunter2-but-longer"), written);
        assertTrue(written.contains("INFO connecting with password [redacted:db]"), written);
        assertTrue(written.contains("password=[redacted:db] refused"), written);
        assertTrue(written.contains("INFO an ordinary line"), written);
    }
}
