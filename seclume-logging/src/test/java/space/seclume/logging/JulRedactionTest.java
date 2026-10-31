package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;
import java.util.logging.XMLFormatter;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.logging.jul.RedactingFormatter;
import space.seclume.tck.StaticSecretProvider;

/**
 * java.util.logging, and System.Logger on top of it: messages, their
 * parameters and stack traces masked by RedactingFormatter around another
 * formatter, a handler wrapped as it is, the formatter named in a logging
 * configuration, and lines without a secret left as they were.
 *
 * <p>Isolated: the installed masker and the LogManager are one per JVM.
 */
@Isolated
class JulRedactionTest {

    private static final String SECRET = "hunter2-but-longer";

    @AfterEach
    void uninstall() throws Exception {
        SecretMasker.install(null);
        LogManager.getLogManager().reset();
        LogManager.getLogManager().readConfiguration();
    }

    /** A logger of its own writing through {@code handler}, and nowhere else. */
    private static Logger logger(String name, Handler handler) {
        Logger logger = Logger.getLogger("seclume.test.jul." + name);
        logger.setUseParentHandlers(false);
        for (Handler old : logger.getHandlers()) {
            logger.removeHandler(old);
        }
        logger.addHandler(handler);
        logger.setLevel(Level.ALL);
        handler.setLevel(Level.ALL);
        return logger;
    }

    private static SecretMasker masker() {
        SecretMasker masker = new SecretMasker(Map.of("db", new StaticSecretProvider(SECRET)));
        SecretMasker.install(masker);
        return masker;
    }

    @Test
    void messagesParametersAndStackTracesAreMasked() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StreamHandler handler = new StreamHandler(out, new RedactingFormatter(new SimpleFormatter()));
        try (SecretMasker _ = masker()) {
            Logger logger = logger("masked", handler);
            logger.info("connecting with password " + SECRET);
            logger.log(Level.WARNING, "a parameter: {0}, and again {0}", SECRET);
            logger.log(Level.SEVERE, "the login failed", new IllegalStateException(
                    "jdbc:postgresql://db/app?password=" + SECRET + " refused"));
            logger.info("an ordinary line");
            handler.flush();
        }
        String written = out.toString(StandardCharsets.UTF_8);
        assertFalse(written.contains(SECRET), written);
        assertTrue(written.contains("connecting with password [redacted:db]"), written);
        assertTrue(written.contains("a parameter: [redacted:db], and again [redacted:db]"), written);
        assertTrue(written.contains("password=[redacted:db] refused"), written);
        assertTrue(written.contains("java.lang.IllegalStateException"), "the stack trace is still there");
        assertTrue(written.contains("an ordinary line"), written);
    }

    @Test
    void theSecretsBase64IsMaskedToo() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StreamHandler handler = new StreamHandler(out, new RedactingFormatter(new SimpleFormatter()));
        String encoded = Base64.getEncoder().encodeToString(SECRET.getBytes(StandardCharsets.UTF_8));
        try (SecretMasker _ = masker()) {
            logger("base64", handler).info("Authorization: Basic " + encoded);
            handler.flush();
        }
        String written = out.toString(StandardCharsets.UTF_8);
        assertFalse(written.contains(encoded), written);
        assertTrue(written.contains("Authorization: Basic [redacted:db]"), written);
    }

    @Test
    void withoutAMaskerNothingChanges() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StreamHandler handler = new StreamHandler(out, new RedactingFormatter(new SimpleFormatter()));
        logger("plain", handler).info("password " + SECRET);
        handler.flush();
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("password " + SECRET),
                "no masker installed: the formatter changes nothing, and logging goes on");
    }

    @Test
    void anXmlDocumentIsMaskedHeadToTail() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StreamHandler handler = new StreamHandler(out, new RedactingFormatter(new XMLFormatter()));
        try (SecretMasker _ = masker()) {
            logger("xml", handler).info("token " + SECRET);
            handler.close();
        }
        String written = out.toString(StandardCharsets.UTF_8);
        assertTrue(written.startsWith("<?xml"), written);
        assertTrue(written.strip().endsWith("</log>"), written);
        assertTrue(written.contains("<message>token [redacted:db]</message>"), written);
        assertFalse(written.contains(SECRET), written);
    }

    @Test
    void aHandlerIsWrappedAsItIsAndOnlyOnce() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Formatter custom = new Formatter() {
            @Override
            public String format(LogRecord record) {
                return "<" + record.getLevel() + "|" + formatMessage(record) + ">\n";
            }
        };
        StreamHandler handler = RedactingFormatter.wrap(new StreamHandler(out, custom));
        assertInstanceOf(RedactingFormatter.class, handler.getFormatter());
        assertSame(custom, ((RedactingFormatter) handler.getFormatter()).delegate());
        Formatter once = handler.getFormatter();
        assertSame(once, RedactingFormatter.wrap(handler).getFormatter(), "not wrapped twice");
        try (SecretMasker _ = masker()) {
            logger("wrapped", handler).warning("key=" + SECRET);
            handler.flush();
        }
        assertEquals("<WARNING|key=[redacted:db]>", out.toString(StandardCharsets.UTF_8).strip());
    }

    @Test
    void theFormatterIsNamedInTheLoggingConfiguration() throws Exception {
        String properties = """
                handlers=java.util.logging.ConsoleHandler
                java.util.logging.ConsoleHandler.formatter=space.seclume.logging.jul.RedactingFormatter
                space.seclume.logging.jul.RedactingFormatter.delegate=java.util.logging.XMLFormatter
                """;
        LogManager.getLogManager().readConfiguration(
                new ByteArrayInputStream(properties.getBytes(StandardCharsets.UTF_8)));
        RedactingFormatter configured = new RedactingFormatter();
        assertInstanceOf(XMLFormatter.class, configured.delegate());
        Handler console = Logger.getLogger("").getHandlers()[0];
        assertInstanceOf(RedactingFormatter.class, console.getFormatter(),
                "the console handler took the formatter from the configuration");

        LogManager.getLogManager().readConfiguration(new ByteArrayInputStream(
                "space.seclume.logging.jul.RedactingFormatter.delegate=com.example.Mine\n"
                        .getBytes(StandardCharsets.UTF_8)));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, RedactingFormatter::new);
        assertTrue(e.getMessage().contains("com.example.Mine"), e.getMessage());

        LogManager.getLogManager().reset();
        assertInstanceOf(SimpleFormatter.class, new RedactingFormatter().delegate(), "the default");
        assertThrows(IllegalArgumentException.class, () -> new RedactingFormatter(null));
    }

    @Test
    void systemLoggerLinesGoThroughItToo() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StreamHandler handler = new StreamHandler(out, new RedactingFormatter(new SimpleFormatter()));
        logger("system", handler);
        try (SecretMasker _ = masker()) {
            System.Logger system = System.getLogger("seclume.test.jul.system");
            system.log(System.Logger.Level.ERROR, "vault answered with {0}", SECRET);
            handler.flush();
        }
        String written = out.toString(StandardCharsets.UTF_8);
        assertFalse(written.contains(SECRET), written);
        assertTrue(written.contains("vault answered with [redacted:db]"), written);
    }

    @Test
    void aRecordWithoutAMessageIsFormattedAsBefore() {
        RedactingFormatter formatter = new RedactingFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                return record.getMessage();
            }
        });
        try (SecretMasker _ = masker()) {
            assertNull(formatter.format(new LogRecord(Level.INFO, null)));
        }
    }
}
