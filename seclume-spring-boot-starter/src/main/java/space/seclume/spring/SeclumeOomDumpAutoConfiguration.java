package space.seclume.spring;

import java.time.Duration;
import java.util.Set;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Redacts the heap dumps this JVM writes on an {@code OutOfMemoryError}
 * ({@link OomDumpRedaction}), on by default wherever it writes any:
 *
 * <ul>
 *   <li>{@code seclume.heapdump.oom.redact=false} leaves them as they are;
 *   <li>{@code seclume.heapdump.oom.folder} watches another folder than
 *       {@code -XX:HeapDumpPath} - one the JVM's dumps are moved to, say;
 *   <li>{@code seclume.heapdump.oom.interval} (30s) is how often it looks;
 *   <li>{@code seclume.heapdump.ignore} leaves detectors out, as for
 *       {@code /actuator/heapdump}.
 * </ul>
 */
@AutoConfiguration
@ConditionalOnClass(name = "space.seclume.heapdump.DumpFolder")
@ConditionalOnProperty(prefix = "seclume.heapdump.oom", name = "redact", havingValue = "true",
        matchIfMissing = true)
public class SeclumeOomDumpAutoConfiguration {

    /**
     * The application's own secrets for every redaction of its heap - here and
     * at {@code /actuator/heapdump}: each data source's, and
     * {@code seclume.heapdump.secrets.<label>.*} as a secret provider's settings.
     */
    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    RedactionSecrets seclumeRedactionSecrets(Environment environment) {
        // Flat, as spring.mail.properties is bound: "api.provider" -> "file".
        java.util.Map<String, String> flat = Binder.get(environment)
                .bind("seclume.heapdump.secrets", Bindable.mapOf(String.class, String.class))
                .orElse(java.util.Map.of());
        java.util.Map<String, java.util.Map<String, String>> byLabel =
                new java.util.TreeMap<>();
        flat.forEach((key, value) -> {
            int dot = key.indexOf('.');
            if (dot <= 0) {
                throw new IllegalArgumentException("seclume.heapdump.secrets." + key
                        + ": a secret is seclume.heapdump.secrets.<label>.<provider setting>");
            }
            byLabel.computeIfAbsent(key.substring(0, dot), label ->
                    new java.util.LinkedHashMap<>()).put(key.substring(dot + 1), value);
        });
        java.util.Map<String, space.seclume.secret.SecretProvider> providers =
                new java.util.LinkedHashMap<>();
        byLabel.forEach((label, settings) -> providers.put("seclume.heapdump.secrets."
                + label, space.seclume.secret.SecretProviders.of(settings)));
        return new RedactionSecrets(providers);
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    OomDumpRedaction seclumeOomDumpRedaction(Environment environment,
            org.springframework.beans.factory.ObjectProvider<RedactionSecrets> secrets) {
        Binder binder = Binder.get(environment);
        Set<String> ignore = binder.bind("seclume.heapdump.ignore", Bindable.setOf(String.class))
                .orElse(Set.of());
        for (String id : ignore) {
            if (!space.seclume.heapdump.Discovery.ids().contains(id)) {
                throw new IllegalArgumentException("seclume.heapdump.ignore: no detector '" + id
                        + "' - known are " + String.join(", ",
                                space.seclume.heapdump.Discovery.ids()));
            }
        }
        Duration interval = binder.bind("seclume.heapdump.oom.interval", Duration.class)
                .orElse(Duration.ofSeconds(30));
        return OomDumpRedaction.start(OomDumpRedaction.folder(
                environment.getProperty("seclume.heapdump.oom.folder"),
                OomDumpRedaction.VmOptions.current()), ignore, interval,
                secrets.getIfAvailable());
    }
}
