package space.seclume.spring;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import space.seclume.logging.SecretMasker;

/**
 * Masks the application's own secrets in its log output, with
 * {@code seclume.logging.redact=true} and seclume-logging on the class path:
 * every data source's password and {@code seclume.heapdump.secrets.<label>.*}
 * - the secrets a heap dump is redacted of - are looked for in each message
 * and stack trace that goes through seclume's Logback converters
 * ({@code redact-rules.xml} included in {@code logback-spring.xml} after
 * Spring Boot's own, or {@code RedactingEncoder}), Log4j 2's {@code %redact{...}} in
 * {@code log4j2-spring.xml}, the {@code RedactingFormatter} of
 * java.util.logging, or {@link SecretMasker#maskInstalled}.
 *
 * <p>The masker keeps no secret, only keyed fingerprints; it reads the secrets
 * again once every bean is made - so that every data source counts - and then
 * every {@code seclume.logging.refresh-interval} (five minutes), so that a
 * rotated secret is looked for.
 */
@AutoConfiguration(after = SeclumeOomDumpAutoConfiguration.class)
@ConditionalOnClass(name = "space.seclume.logging.SecretMasker")
@ConditionalOnProperty(prefix = "seclume.logging", name = "redact", havingValue = "true")
public class SeclumeLogRedactionAutoConfiguration {

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    LogRedaction seclumeLogRedaction(ObjectProvider<RedactionSecrets> secrets,
            Environment environment) {
        // Bound, not read: the Environment converts no "5m" to a Duration.
        Duration interval = Binder.get(environment)
                .bind("seclume.logging.refresh-interval", Duration.class)
                .orElse(Duration.ofMinutes(5));
        if (interval.isNegative() || interval.isZero()) {
            throw new IllegalStateException("seclume.logging.refresh-interval is how often the "
                    + "secrets are read again - a positive duration, not " + interval);
        }
        boolean strict = Binder.get(environment)
                .bind("seclume.logging.redact.strict", Boolean.class).orElse(false);
        return new LogRedaction(() -> {
            RedactionSecrets found = secrets.getIfAvailable();
            return found == null ? Map.of() : found.providers();
        }, interval, strict);
    }

    private static final System.Logger LOG =
            System.getLogger(SeclumeLogRedactionAutoConfiguration.class.getName());

    /**
     * The masker is installed; whether Logback uses it is another matter.
     * Without seclume's converters in its configuration - no
     * {@code logback-spring.xml} including {@code redact-rules.xml}, no
     * {@code RedactingEncoder} - not one line is masked, and the switch looked
     * like protection. Said at start; refused with
     * {@code seclume.logging.redact.strict=true}.
     *
     * @return the warning, or null when there is nothing to say
     */
    static String checkLogback(Boolean active, boolean strict) {
        if (active == null || active) {
            return null;                            // not Logback, or Logback masks
        }
        String warning = "seclume: seclume.logging.redact=true, and Logback masks nothing - no "
                + "converter or encoder of seclume's is in its configuration. Include "
                + "space/seclume/logging/logback/redact-rules.xml after Spring Boot's "
                + "defaults.xml in logback-spring.xml, or wrap the encoder in a RedactingEncoder.";
        if (strict) {
            throw new IllegalStateException(warning + " Refused to start because "
                    + "seclume.logging.redact.strict=true asks for masking that works.");
        }
        LOG.log(System.Logger.Level.WARNING, warning);
        return warning;
    }

    private static Boolean logbackMasks() {
        if (!org.springframework.util.ClassUtils.isPresent("ch.qos.logback.classic.LoggerContext",
                SeclumeLogRedactionAutoConfiguration.class.getClassLoader())) {
            return null;
        }
        return space.seclume.logging.logback.LogbackMasking.active();
    }

    /** The installed masker, refreshed on a schedule; closing it uninstalls it. */
    public static final class LogRedaction implements SmartInitializingSingleton, AutoCloseable {

        private final SecretMasker masker;
        private final ScheduledExecutorService refresher;
        private final boolean strict;

        LogRedaction(java.util.function.Supplier<Map<String, space.seclume.secret.SecretProvider>>
                providers, Duration interval, boolean strict) {
            this.strict = strict;
            this.masker = new SecretMasker(providers);
            SecretMasker.install(masker);
            this.refresher = Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "seclume-log-redaction");
                thread.setDaemon(true);
                return thread;
            });
            refresher.scheduleWithFixedDelay(masker::refresh, interval.toMillis(),
                    interval.toMillis(), TimeUnit.MILLISECONDS);
        }

        /** The masker in use. */
        public SecretMasker masker() {
            return masker;
        }

        /** Every bean is made, every data source registered: read them all. */
        @Override
        public void afterSingletonsInstantiated() {
            masker.refresh();
            checkLogback(logbackMasks(), strict);
        }

        @Override
        public void close() {
            refresher.shutdownNow();
            masker.close();
        }
    }
}
