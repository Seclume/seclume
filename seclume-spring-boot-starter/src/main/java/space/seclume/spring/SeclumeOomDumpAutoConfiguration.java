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

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    OomDumpRedaction seclumeOomDumpRedaction(Environment environment) {
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
                OomDumpRedaction.VmOptions.current()), ignore, interval);
    }
}
