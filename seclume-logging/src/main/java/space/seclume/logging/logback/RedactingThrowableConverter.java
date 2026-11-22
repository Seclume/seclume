package space.seclume.logging.logback;

import ch.qos.logback.classic.pattern.ExtendedThrowableProxyConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import space.seclume.logging.SecretMasker;

/**
 * Logback's stack trace with packaging data ({@code %xEx}, {@code %xException},
 * {@code %xThrowable}) with the application's secrets masked: an exception's
 * message is where a connection string with its password, or a token a
 * client refused, likes to turn up.
 *
 * <p>The other stack trace words have converters of their own -
 * {@link RedactingThrowableProxyConverter} for {@code %ex}, {@code %exception}
 * and {@code %throwable}, {@link RedactingRootCauseFirstConverter} for
 * {@code %rEx}, and Spring Boot's {@code %wex} and {@code %wEx} - and
 * {@code redact-rules.xml} registers them all. A pattern with no stack trace
 * word gets Logback's own converter, which no rule replaces:
 * {@link RedactingEncoder} masks that too.
 */
public class RedactingThrowableConverter extends ExtendedThrowableProxyConverter {

    @Override
    public String convert(ILoggingEvent event) {
        return SecretMasker.maskInstalled(super.convert(event));
    }
}
