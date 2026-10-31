package space.seclume.spring;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import space.seclume.inventory.CryptoInventory;
import space.seclume.inventory.CryptoPolicy;

/**
 * The crypto policy, from {@code application.properties}:
 *
 * <pre>
 *   seclume.crypto-policy.rules.rsa.min-bits=3072
 *   seclume.crypto-policy.rules.tls.require-hybrid=true
 *   seclume.crypto-policy.rules.secret.forbidden-providers=file
 *   seclume.crypto-policy.on-start=fail      # off, warn (default) or fail
 * </pre>
 *
 * <p>The rules are {@link CryptoPolicy}'s. At start-up - after the context is
 * up, when the pools have made their first connections - the inventory is
 * checked: {@code warn} logs the findings, {@code fail} stops the application
 * on a failing one. With the health API on the class path the
 * {@code cryptoPolicy} health contributor goes {@code DOWN} while the policy
 * fails - for a deployment that should not take traffic on a downgraded TLS
 * session or a certificate about to lapse. With the actuator,
 * {@code /actuator/quantum} is the post-quantum readiness report.
 *
 * <p>{@code seclume.crypto-policy.enabled=false} turns all of it off.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "seclume.crypto-policy", name = "enabled", matchIfMissing = true)
public class SeclumeCryptoPolicyAutoConfiguration {

    static final String PREFIX = "seclume.crypto-policy";
    private static final System.Logger LOG =
            System.getLogger(SeclumeCryptoPolicyAutoConfiguration.class.getName());

    /** The policy the properties describe; the defaults when there are none. */
    @Bean
    @ConditionalOnMissingBean
    CryptoPolicy seclumeCryptoPolicy(Environment environment) {
        return policy(environment);
    }

    static CryptoPolicy policy(Environment environment) {
        Map<String, String> rules = Binder.get(environment).bind(PREFIX + ".rules",
                Bindable.mapOf(String.class, String.class)).orElse(Map.of());
        return CryptoPolicy.of(new LinkedHashMap<>(rules));
    }

    /** The check at start-up. */
    @Bean
    ApplicationRunner seclumeCryptoPolicyCheck(CryptoPolicy policy, Environment environment) {
        String onStart = environment.getProperty(PREFIX + ".on-start", "warn")
                .trim().toLowerCase(Locale.ROOT);
        if (!List.of("off", "warn", "fail").contains(onStart)) {
            throw new IllegalArgumentException(PREFIX + ".on-start is off, warn or fail, not "
                    + onStart);
        }
        return new StartCheck(policy, onStart);
    }

    /** Checks once; {@code fail} turns a failing finding into a failed start. */
    static final class StartCheck implements ApplicationRunner {

        private final CryptoPolicy policy;
        private final String onStart;

        StartCheck(CryptoPolicy policy, String onStart) {
            this.policy = policy;
            this.onStart = onStart;
        }

        @Override
        public void run(ApplicationArguments arguments) {
            if (onStart.equals("off")) {
                return;
            }
            List<CryptoPolicy.Finding> findings = policy.check(CryptoInventory.snapshot(),
                    Instant.now());
            for (CryptoPolicy.Finding finding : findings) {
                LOG.log(finding.severity() == CryptoPolicy.Severity.FAIL
                        ? System.Logger.Level.ERROR : System.Logger.Level.WARNING,
                        "crypto policy " + finding.rule() + ": " + finding.message());
            }
            if (onStart.equals("fail") && CryptoPolicy.fails(findings)) {
                throw new IllegalStateException("the crypto policy is not met ("
                        + findings.stream().filter(f -> f.severity() == CryptoPolicy.Severity.FAIL)
                                .count() + " failing): "
                        + findings.get(0).message() + " - see the log for the rest, or set "
                        + PREFIX + ".on-start=warn");
            }
        }
    }

    /** {@code cryptoPolicy} in the health tree - only when the health API is there. */
    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.health.contributor.HealthIndicator")
    static class HealthConfiguration {

        @Bean(name = "cryptoPolicyHealthIndicator")
        @ConditionalOnMissingBean(SeclumeCryptoPolicyHealth.class)
        SeclumeCryptoPolicyHealth seclumeCryptoPolicyHealth(CryptoPolicy policy) {
            return new SeclumeCryptoPolicyHealth(policy);
        }
    }

    /** {@code /actuator/quantum} - only when the actuator is there. */
    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.actuate.endpoint.annotation.Endpoint")
    static class EndpointConfiguration {

        @Bean
        @ConditionalOnMissingBean
        SeclumeQuantumEndpoint seclumeQuantumEndpoint() {
            return new SeclumeQuantumEndpoint();
        }
    }
}
