package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * seclume.logging.redact=true installs the masker; without seclume's
 * converters in Logback's configuration not one line was masked, and the
 * switch looked like protection. The starter says so at start, and with
 * seclume.logging.redact.strict=true refuses to start.
 */
class LogbackMaskingCheckTest {

    @Test
    void logbackWithoutSeclumesConvertersIsAWarning() {
        String warning = SeclumeLogRedactionAutoConfiguration.checkLogback(false, false);
        assertNotNull(warning);
        assertTrue(warning.contains("redact-rules.xml"), warning);
    }

    @Test
    void strictRefusesToStart() {
        assertThrows(IllegalStateException.class,
                () -> SeclumeLogRedactionAutoConfiguration.checkLogback(false, true));
    }

    @Test
    void maskingLogbackOrAnotherLoggerIsNothingToSay() {
        assertNull(SeclumeLogRedactionAutoConfiguration.checkLogback(true, true));
        assertNull(SeclumeLogRedactionAutoConfiguration.checkLogback(null, true));
    }
}
