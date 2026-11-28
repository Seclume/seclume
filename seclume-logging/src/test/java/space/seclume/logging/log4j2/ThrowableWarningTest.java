package space.seclume.logging.log4j2;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.logging.log4j.core.config.DefaultConfiguration;
import org.junit.jupiter.api.Test;

/**
 * Without a stack trace word inside %redact{...}, Log4j's layout appends the
 * stack trace after the converter - unmasked, and silently. The status log
 * says so now.
 */
class ThrowableWarningTest {

    @Test
    void aPatternWithoutAStackTraceWordIsWarnedAbout() {
        RedactingConverter converter = RedactingConverter.newInstance(new DefaultConfiguration(),
                new String[] {"%msg%n"});
        assertFalse(converter.handlesThrowable());
        String warning = RedactingConverter.throwableWarning("%msg%n", false);
        assertNotNull(warning);
        assertTrue(warning.contains("%throwable"), warning);
    }

    @Test
    void aPatternWithOneIsNot() {
        RedactingConverter converter = RedactingConverter.newInstance(new DefaultConfiguration(),
                new String[] {"%msg%n%throwable"});
        assertTrue(converter.handlesThrowable());
        assertNull(RedactingConverter.throwableWarning("%msg%n%throwable", true));
    }

    /** A truncation inside %redact cuts a secret before it can be recognized - said at start. */
    @Test
    void aTruncationInsideIsWarnedAbout() {
        for (String pattern : new String[] {"%.20msg%n%throwable", "%-10.30m%ex", "%.-40message"}) {
            String warning = RedactingConverter.precisionWarning(pattern);
            assertTrue(warning != null && warning.contains("Truncate outside"), pattern);
        }
        for (String pattern : new String[] {"%msg%n%throwable", "%-20level %msg", "%d{HH:mm:ss.SSS} %m"}) {
            assertNull(RedactingConverter.precisionWarning(pattern), pattern);
        }
    }
}
