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
 * ({@code conversionRule} for {@code msg} and {@code xEx} in
 * {@code logback-spring.xml}), or through {@link SecretMasker#maskInstalled}.
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
        return new LogRedaction(() -> {
            RedactionSecrets found = secrets.getIfAvailable();
            return found == null ? Map.of() : found.providers();
        }, interval);
    }

    /** The installed masker, refreshed on a schedule; closing it uninstalls it. */
    public static final class LogRedaction implements SmartInitializingSingleton, AutoCloseable {

        private final SecretMasker masker;
        private final ScheduledExecutorService refresher;

        LogRedaction(java.util.function.Supplier<Map<String, space.seclume.secret.SecretProvider>>
                providers, Duration interval) {
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
        }

        @Override
        public void close() {
            refresher.shutdownNow();
            masker.close();
        }
    }
}
