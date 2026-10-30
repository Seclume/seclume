package space.seclume.logging.logback;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import space.seclume.logging.SecretMasker;

/**
 * Logback's {@code %msg} with the application's secrets masked by the
 * installed {@link SecretMasker}:
 *
 * <pre>
 * &lt;conversionRule conversionWord="msg"
 *                 class="space.seclume.logging.logback.RedactingMessageConverter"/&gt;
 * </pre>
 *
 * <p>Registered under {@code msg} (and {@code m}, {@code message}) it replaces
 * Logback's own, so that every pattern that writes the message masks it.
 */
public class RedactingMessageConverter extends MessageConverter {

    @Override
    public String convert(ILoggingEvent event) {
        return SecretMasker.maskInstalled(super.convert(event));
    }
}
