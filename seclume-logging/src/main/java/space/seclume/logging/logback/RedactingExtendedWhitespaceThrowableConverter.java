package space.seclume.logging.logback;

import ch.qos.logback.classic.pattern.ExtendedThrowableProxyConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.CoreConstants;

import space.seclume.logging.SecretMasker;

/**
 * {@code %wEx}, the word that ends every pattern of Spring Boot's Logback
 * configuration - the stack trace with packaging data and a line break before
 * and after it - with the application's secrets masked by the installed
 * {@link SecretMasker}. Spring Boot's {@code defaults.xml} registers its own
 * converter under the word, so {@code redact-rules.xml} has to be included
 * after it.
 */
public class RedactingExtendedWhitespaceThrowableConverter extends ExtendedThrowableProxyConverter {

    @Override
    protected String throwableProxyToString(IThrowableProxy throwable) {
        return CoreConstants.LINE_SEPARATOR + super.throwableProxyToString(throwable)
                + CoreConstants.LINE_SEPARATOR;
    }

    @Override
    public String convert(ILoggingEvent event) {
        return SecretMasker.maskInstalled(super.convert(event));
    }
}
