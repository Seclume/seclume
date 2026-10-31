package space.seclume.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/** {@code /actuator/cbom} - only when the actuator is on the class path. */
@AutoConfiguration
@ConditionalOnClass(name = "org.springframework.boot.actuate.endpoint.annotation.Endpoint")
public class SeclumeCbomAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    SeclumeCbomEndpoint seclumeCbomEndpoint(Environment environment) {
        return new SeclumeCbomEndpoint(environment.getProperty("spring.application.name",
                "application"));
    }
}
