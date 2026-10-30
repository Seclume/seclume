package space.seclume.logging.logback;

import ch.qos.logback.classic.pattern.ExtendedThrowableProxyConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import space.seclume.logging.SecretMasker;

/**
 * Logback's stack trace ({@code %ex}, {@code %xEx}) with the application's
 * secrets masked: an exception's message is where a connection string with
 * its password, or a token a client refused, likes to turn up.
 *
 * <pre>
 * &lt;conversionRule conversionWord="xEx"
 *                 converterClass="space.seclume.logging.logback.RedactingThrowableConverter"/&gt;
 * </pre>
 */
public class RedactingThrowableConverter extends ExtendedThrowableProxyConverter {

    @Override
    public String convert(ILoggingEvent event) {
        return SecretMasker.maskInstalled(super.convert(event));
    }
}
