package space.seclume.logging.logback;

import ch.qos.logback.classic.pattern.ThrowableProxyConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import space.seclume.logging.SecretMasker;

/**
 * Logback's {@code %ex}, {@code %exception} and {@code %throwable} - the stack
 * trace without packaging data - with the application's secrets masked by the
 * installed {@link SecretMasker}. {@code redact-rules.xml} registers it under
 * those words; see {@link RedactingEncoder} for a whole line.
 */
public class RedactingThrowableProxyConverter extends ThrowableProxyConverter {

    @Override
    public String convert(ILoggingEvent event) {
        return SecretMasker.maskInstalled(super.convert(event));
    }
}
