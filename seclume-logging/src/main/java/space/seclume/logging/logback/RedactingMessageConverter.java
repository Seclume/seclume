package space.seclume.logging.logback;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import space.seclume.logging.SecretMasker;

/**
 * Logback's {@code %m}, {@code %msg} and {@code %message} with the
 * application's secrets masked by the installed {@link SecretMasker}.
 *
 * <p>A conversion rule replaces Logback's converter for its one word only:
 * Spring Boot's patterns write {@code %m}, so a rule for {@code msg} alone
 * leaves their messages as they were. {@code redact-rules.xml} registers this
 * converter under all three words, and the stack trace converters under theirs:
 *
 * <pre>
 * &lt;include resource="space/seclume/logging/logback/redact-rules.xml"/&gt;
 * </pre>
 *
 * <p>{@link RedactingEncoder} masks a whole line instead - every word, the
 * MDC, a stack trace Logback adds by itself, a structured encoder's output.
 */
public class RedactingMessageConverter extends MessageConverter {

    /** Starts, and warns where a rule for a stack trace word replaced seclume's. */
    @Override
    public void start() {
        super.start();
        RuleCheck.warnAboutOtherRules(this);
    }

    @Override
    public String convert(ILoggingEvent event) {
        return SecretMasker.maskInstalled(super.convert(event));
    }
}
