package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.util.LogbackMDCAdapter;
import ch.qos.logback.core.CoreConstants;
import ch.qos.logback.core.encoder.EncoderBase;
import ch.qos.logback.core.status.Status;

import space.seclume.logging.logback.RedactingEncoder;
import space.seclume.tck.StaticSecretProvider;

/**
 * Every word Logback and Spring Boot's patterns write a message or a stack
 * trace with is masked once redact-rules.xml is included - after rules of
 * Spring Boot's own for wex and wEx, and after the appenders - and
 * RedactingEncoder masks what no rule reaches: the stack trace Logback adds
 * to a pattern without one, the MDC, a JSON encoder's output. Isolated: the
 * installed masker is one for the whole JVM.
 */
@Isolated
class LogbackCoverageTest {

    private static final String SECRET = "Qz-decoy-log-secret-4711";

    @TempDir
    Path directory;

    /** What the last configuration reported in Logback's status. */
    private List<Status> statuses = List.of();

    /** Spring Boot's defaults.xml registers converters of its own under these two words. */
    private static final String SPRING_LIKE_RULES = """
              <conversionRule conversionWord="wex" class="ch.qos.logback.classic.pattern.ThrowableProxyConverter"/>
              <conversionRule conversionWord="wEx" class="ch.qos.logback.classic.pattern.ExtendedThrowableProxyConverter"/>
            """;

    private static final String RULES =
            "  <include resource=\"space/seclume/logging/logback/redact-rules.xml\"/>\n";

    private List<String> written(String before, List<String> encoders, String after) throws Exception {
        StringBuilder appenders = new StringBuilder();
        StringBuilder refs = new StringBuilder();
        for (int i = 0; i < encoders.size(); i++) {
            appenders.append("""
                      <appender name="A%d" class="ch.qos.logback.core.FileAppender">
                        <file>%s</file>
                        %s
                      </appender>
                    """.formatted(i, directory.resolve("a" + i + ".log"), encoders.get(i)));
            refs.append("<appender-ref ref=\"A").append(i).append("\"/>");
        }
        String xml = "<configuration>\n" + before + appenders + "<root level=\"INFO\">" + refs
                + "</root>\n" + after + "</configuration>\n";
        LoggerContext context = new LoggerContext();
        context.setMDCAdapter(new LogbackMDCAdapter());
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(context);
        configurator.doConfigure(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        try (SecretMasker masker = new SecretMasker(Map.of("db", new StaticSecretProvider(SECRET)))) {
            SecretMasker.install(masker);
            context.getMDCAdapter().put("token", SECRET);
            Logger logger = context.getLogger("app");
            logger.warn("connecting with password {}", SECRET, new IllegalStateException(
                    "jdbc:postgresql://db/app?password=" + SECRET + " refused"));
            context.getMDCAdapter().clear();
            statuses = context.getStatusManager().getCopyOfStatusList();
            context.stop();
        } finally {
            SecretMasker.install(null);
        }
        List<String> out = new ArrayList<>();
        for (int i = 0; i < encoders.size(); i++) {
            Path file = directory.resolve("a" + i + ".log");
            out.add(Files.exists(file) ? Files.readString(file) : "");
        }
        return out;
    }

    private static String pattern(String pattern) {
        return "<encoder><pattern>" + pattern + "</pattern></encoder>";
    }

    private static int masks(String written) {
        return written.split("\\[redacted:db]", -1).length - 1;
    }

    @Test
    void everyMessageAndStackTraceWordIsMaskedWithTheRules() throws Exception {
        List<String> patterns = List.of(
                // Spring Boot's FILE_LOG_PATTERN, the part that writes message and stack trace
                "%d ${LOG_LEVEL_PATTERN:-%5p} --- [%t] %-40.40logger{39} : %m%n${LOG_EXCEPTION_CONVERSION_WORD:-%wEx}",
                "%m%n%wex", "%msg%n%ex", "%message%n%exception", "%m%n%throwable",
                "%m%n%rEx", "%m%n%rootException", "%m%n%xEx", "%m%n%xException", "%m%n%xThrowable");
        List<String> written = written(SPRING_LIKE_RULES + RULES,
                patterns.stream().map(LogbackCoverageTest::pattern).toList(), "");
        for (int i = 0; i < patterns.size(); i++) {
            String file = written.get(i);
            assertFalse(file.contains(SECRET), patterns.get(i) + ":\n" + file);
            assertEquals(2, masks(file), patterns.get(i) + ": message and stack trace\n" + file);
            assertTrue(file.contains("IllegalStateException"), patterns.get(i) + ":\n" + file);
        }
        // %wex and %wEx keep Spring Boot's blank line before the stack trace.
        for (int i : new int[] {0, 1}) {
            assertTrue(written.get(i).contains("[redacted:db]" + CoreConstants.LINE_SEPARATOR
                    + CoreConstants.LINE_SEPARATOR + "java.lang.IllegalStateException"), written.get(i));
        }
    }

    @Test
    void theRulesApplyIncludedAfterTheAppenders() throws Exception {
        // As after <include resource="org/springframework/boot/logging/logback/base.xml"/>:
        // Spring Boot's rules and appenders first, then seclume's rules.
        List<String> written = written(SPRING_LIKE_RULES, List.of(pattern("%m%n%wEx")), RULES);
        assertFalse(written.get(0).contains(SECRET), written.get(0));
        assertEquals(2, masks(written.get(0)), written.get(0));
    }

    private boolean reported(int level, String text) {
        return statuses.stream().anyMatch(status -> status.getLevel() == level
                && status.getMessage().contains(text));
    }

    @Test
    void rulesIncludedBeforeSpringBootsAreReported() throws Exception {
        // Included first, Spring Boot's later rules replace %wex and %wEx: the
        // message is masked, the stack trace is not - and Logback's status says so.
        List<String> written = written(RULES + SPRING_LIKE_RULES, List.of(pattern("%m%n%wEx")), "");
        assertEquals(1, masks(written.get(0)), written.get(0));
        assertTrue(reported(Status.WARN, "%wEx, %wex are not masked"), statuses.toString());
        written(SPRING_LIKE_RULES + RULES, List.of(pattern("%m%n%wEx")), "");
        assertFalse(reported(Status.WARN, "are not masked"), statuses.toString());
    }

    @Test
    void anEncoderThatDidNotStartWritesNothing() throws Exception {
        // Neither a pattern nor an encoder: the configuration goes on, the
        // error is in the status, and no line is written - not one unmasked.
        List<String> written = written("", List.of(
                "<encoder class=\"space.seclume.logging.logback.RedactingEncoder\"/>",
                pattern("%m%n")), "");
        assertEquals("", written.get(0));
        assertTrue(reported(Status.ERROR, "RedactingEncoder takes a <pattern> or an <encoder>"),
                statuses.toString());
        assertTrue(written.get(1).contains(SECRET), "the other appender is configured: " + written.get(1));
    }

    @Test
    void theEncoderMasksWhatNoRuleReaches() throws Exception {
        String json = """
                <encoder class="space.seclume.logging.logback.RedactingEncoder">
                  <encoder class="ch.qos.logback.classic.encoder.JsonEncoder"/>
                </encoder>""";
        String patterned = """
                <encoder class="space.seclume.logging.logback.RedactingEncoder">
                  <pattern>%level %msg token=%X{token}%n</pattern>
                  <charset>UTF-8</charset>
                </encoder>""";
        List<String> written = written("", List.of(patterned, json, pattern("%level %msg token=%X{token}%n")), "");
        String lines = written.get(0);
        assertFalse(lines.contains(SECRET), lines);
        // message, MDC, and the stack trace Logback adds to a pattern without one
        assertEquals(3, masks(lines), lines);
        assertTrue(lines.contains("WARN connecting with password [redacted:db] token=[redacted:db]"), lines);
        assertTrue(lines.contains("java.lang.IllegalStateException"), lines);
        String structured = written.get(1);
        assertFalse(structured.contains(SECRET), structured);
        assertTrue(structured.contains("\"message\""), structured);
        assertTrue(masks(structured) >= 2, structured);
        // Without the encoder, a pattern masks nothing: there are no rules here.
        assertTrue(written.get(2).contains(SECRET), written.get(2));
    }

    @Test
    void anEncoderTakesAPatternOrAnEncoder() {
        LoggerContext context = new LoggerContext();
        RedactingEncoder neither = new RedactingEncoder();
        neither.setContext(context);
        neither.start();
        assertFalse(neither.isStarted());
        RedactingEncoder both = new RedactingEncoder();
        both.setContext(context);
        both.setPattern("%msg");
        both.setEncoder(new Fixed(new byte[] {'x'}));
        both.start();
        assertFalse(both.isStarted());
    }

    @Test
    void bytesThatAreNotTextAreWrittenAsTheyWere() {
        byte[] secret = SECRET.getBytes(StandardCharsets.US_ASCII);
        byte[] line = new byte[secret.length + 4];
        line[0] = (byte) 0xff;                    // never UTF-8
        line[1] = ' ';
        System.arraycopy(secret, 0, line, 2, secret.length);
        line[line.length - 2] = (byte) 0xfe;
        line[line.length - 1] = '\n';
        RedactingEncoder encoder = new RedactingEncoder();
        encoder.setContext(new LoggerContext());
        encoder.setEncoder(new Fixed(line));
        encoder.start();
        assertTrue(encoder.isStarted());
        try (SecretMasker masker = new SecretMasker(Map.of("db", new StaticSecretProvider(SECRET)))) {
            SecretMasker.install(masker);
            byte[] masked = encoder.encode(null);
            byte[] expected = new byte[] {(byte) 0xff, ' ', '[', 'r', 'e', 'd', 'a', 'c', 't', 'e', 'd',
                    ':', 'd', 'b', ']', (byte) 0xfe, '\n'};
            assertArrayEquals(expected, masked);
            byte[] ordinary = "an ordinary line\n".getBytes(StandardCharsets.UTF_8);
            RedactingEncoder same = new RedactingEncoder();
            same.setContext(new LoggerContext());
            same.setEncoder(new Fixed(ordinary));
            same.start();
            assertTrue(ordinary == same.encode(null), "a line without a secret is the encoder's own bytes");
        } finally {
            SecretMasker.install(null);
        }
    }

    /** An encoder that writes the same bytes for every event. */
    private static final class Fixed extends EncoderBase<ILoggingEvent> {
        private final byte[] bytes;

        Fixed(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public byte[] headerBytes() {
            return null;
        }

        @Override
        public byte[] encode(ILoggingEvent event) {
            return bytes;
        }

        @Override
        public byte[] footerBytes() {
            return null;
        }
    }
}
