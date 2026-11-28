package space.seclume.logging.logback;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import ch.qos.logback.classic.LoggerContext;

/**
 * seclume.logging.redact=true without seclume's converters in Logback's
 * configuration masked nothing, and nothing said so. A converter or encoder
 * of seclume's marks its context when it starts; the starter asks for the mark.
 */
class LogbackMaskingTest {

    @Test
    void aContextWithoutSeclumesConvertersIsNotMarked() {
        LoggerContext plain = new LoggerContext();
        assertFalse(LogbackMasking.marked(plain));
    }

    @Test
    void theEncoderMarksItsContext() {
        LoggerContext context = new LoggerContext();
        RedactingEncoder encoder = new RedactingEncoder();
        encoder.setContext(context);
        encoder.setPattern("%msg%n");
        encoder.start();
        assertTrue(encoder.isStarted());
        assertTrue(LogbackMasking.marked(context));
    }

    @Test
    void theMessageConverterMarksItsContext() {
        LoggerContext context = new LoggerContext();
        RedactingMessageConverter converter = new RedactingMessageConverter();
        converter.setContext(context);
        converter.start();
        assertTrue(LogbackMasking.marked(context));
    }
}
