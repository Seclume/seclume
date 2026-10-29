package space.seclume.spring;

import java.util.Set;

import org.springframework.boot.actuate.management.HeapDumpWebEndpoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Puts {@link SeclumeHeapDumpWebEndpoint} in the place of Spring Boot's
 * {@code /actuator/heapdump}, so that the endpoint - wherever it is exposed -
 * serves a redacted copy. Before Boot's own configuration, whose bean steps
 * aside for this one.
 *
 * <ul>
 *   <li>{@code seclume.heapdump.redact=false} leaves Boot's endpoint as it is;
 *   <li>{@code seclume.heapdump.ignore=jwt,url-password} leaves detectors out
 *       of the redaction, as {@code seclume-heapcheck --ignore} does. An
 *       unknown one stops the application from starting: a typo would
 *       otherwise leave in what was meant to go.
 * </ul>
 *
 * <p>Exposing the endpoint is still the application's decision, and Boot's
 * default leaves it off.
 */
@AutoConfiguration(beforeName =
        "org.springframework.boot.actuate.autoconfigure.management.HeapDumpWebEndpointAutoConfiguration")
@ConditionalOnClass(name = {
    "org.springframework.boot.actuate.management.HeapDumpWebEndpoint",
    "space.seclume.heapdump.Redactor"})
@ConditionalOnProperty(prefix = "seclume.heapdump", name = "redact", havingValue = "true",
        matchIfMissing = true)
public class SeclumeHeapDumpAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(HeapDumpWebEndpoint.class)
    SeclumeHeapDumpWebEndpoint seclumeHeapDumpWebEndpoint(Environment environment) {
        Set<String> ignore = Binder.get(environment)
                .bind("seclume.heapdump.ignore", Bindable.setOf(String.class))
                .orElse(Set.of());
        return new SeclumeHeapDumpWebEndpoint(ignore);
    }
}
