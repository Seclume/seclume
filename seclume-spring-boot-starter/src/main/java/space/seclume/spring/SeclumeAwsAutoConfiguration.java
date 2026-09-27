package space.seclume.spring;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import io.awspring.cloud.autoconfigure.AwsAsyncClientCustomizer;
import io.awspring.cloud.autoconfigure.AwsSyncClientCustomizer;
import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder;

import space.seclume.aws.SeclumeAws;

/**
 * The AWS secret access key off the heap, for every client Spring Cloud AWS
 * makes - S3, SQS (also its listeners), SNS, DynamoDB, SES ...:
 *
 * <pre>
 * seclume.aws.access-key-id=AKIA...
 * seclume.aws.secret-access-key=provider=file&amp;path=/run/secrets/aws-secret-key
 * seclume.aws.region=eu-central-1                  (optional, else Spring Cloud AWS's)
 *
 * seclume.aws.credentials=web-identity             (instead: temporary credentials -
 *                                                   instance, container or web-identity)
 * </pre>
 *
 * <p>{@code secret-access-key} names the key's secret provider, never the key.
 * Two customizers - one for synchronous, one for asynchronous clients - hand
 * each client builder to {@link SeclumeAws#configure}; Spring Cloud AWS applies
 * them after its own settings, so they replace its credentials provider.
 * Without Spring Cloud AWS, {@code SeclumeAws.configure(S3Client.builder(), ...)}
 * does the same by hand.
 *
 * <p>Temporary credentials need seclume's TLS as the HTTP transport, which
 * the SDK's asynchronous clients cannot use: with {@code credentials=} only the
 * synchronous clients are customized, and the asynchronous ones keep Spring
 * Cloud AWS's own credentials.
 */
@AutoConfiguration
@ConditionalOnClass(name = {"space.seclume.aws.SeclumeAws",
        "io.awspring.cloud.autoconfigure.AwsSyncClientCustomizer"})
@org.springframework.context.annotation.Conditional(SeclumeAwsAutoConfiguration.Configured.class)
public class SeclumeAwsAutoConfiguration {

    /** {@code seclume.aws.access-key-id} or {@code seclume.aws.credentials} is set. */
    static final class Configured implements org.springframework.context.annotation.Condition {
        @Override
        public boolean matches(org.springframework.context.annotation.ConditionContext context,
                               org.springframework.core.type.AnnotatedTypeMetadata metadata) {
            return context.getEnvironment().containsProperty("seclume.aws.access-key-id")
                    || context.getEnvironment().containsProperty("seclume.aws.credentials");
        }
    }

    static boolean temporary(Environment environment) {
        String credentials = environment.getProperty("seclume.aws.credentials", "static");
        return !credentials.equals("static");
    }

    static String spec(Environment environment) {
        if (temporary(environment)) {
            String region = environment.getProperty("seclume.aws.region");
            return "credentials=" + URLEncoder.encode(environment.getRequiredProperty(
                    "seclume.aws.credentials"), StandardCharsets.UTF_8)
                    + (region == null ? "" : "&region=" + URLEncoder.encode(region,
                            StandardCharsets.UTF_8));
        }
        String accessKeyId = environment.getRequiredProperty("seclume.aws.access-key-id");
        String secret = environment.getProperty("seclume.aws.secret-access-key");
        if (secret == null || !secret.contains("provider=")) {
            throw new IllegalStateException("seclume.aws.secret-access-key names the key's "
                    + "secret provider, e.g. provider=file&path=/run/secrets/aws-secret-key - "
                    + "never the key");
        }
        String region = environment.getProperty("seclume.aws.region");
        return "access-key-id=" + URLEncoder.encode(accessKeyId, StandardCharsets.UTF_8)
                + (region == null ? "" : "&region=" + URLEncoder.encode(region,
                        StandardCharsets.UTF_8))
                + "&" + secret;
    }

    @Bean
    public AwsSyncClientCustomizer seclumeAwsSyncClients(Environment environment) {
        String spec = spec(environment);
        return builder -> configure(builder, spec);
    }

    @Bean
    @org.springframework.context.annotation.Conditional(Static.class)
    public AwsAsyncClientCustomizer seclumeAwsAsyncClients(Environment environment) {
        String spec = spec(environment);
        return builder -> configure(builder, spec);
    }

    /** A long-term key - which asynchronous clients can sign with too. */
    static final class Static implements org.springframework.context.annotation.Condition {
        @Override
        public boolean matches(org.springframework.context.annotation.ConditionContext context,
                               org.springframework.core.type.AnnotatedTypeMetadata metadata) {
            return !temporary(context.getEnvironment());
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static void configure(Object builder, String spec) {
        if (!(builder instanceof AwsClientBuilder client)) {
            throw new IllegalStateException(builder.getClass().getName() + " is not an AWS "
                    + "client builder");
        }
        SeclumeAws.configure(client, spec);
    }
}
