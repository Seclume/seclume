package space.seclume.logging.logback;

import ch.qos.logback.classic.pattern.RootCauseFirstThrowableProxyConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import space.seclume.logging.SecretMasker;

/**
 * Logback's {@code %rEx} and {@code %rootException} - the stack trace with its
 * root cause first - with the application's secrets masked by the installed
 * {@link SecretMasker}. {@code redact-rules.xml} registers it under those words.
 */
public class RedactingRootCauseFirstConverter extends RootCauseFirstThrowableProxyConverter {

    @Override
    public String convert(ILoggingEvent event) {
        return SecretMasker.maskInstalled(super.convert(event));
    }
}
