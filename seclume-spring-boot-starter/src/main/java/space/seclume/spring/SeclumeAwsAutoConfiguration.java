package space.seclume.spring;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
 * </pre>
 *
 * <p>{@code secret-access-key} names the key's secret provider, never the key.
 * Two customizers - one for synchronous, one for asynchronous clients - hand
 * each client builder to {@link SeclumeAws#configure}; Spring Cloud AWS applies
 * them after its own settings, so they replace its credentials provider.
 * Without Spring Cloud AWS, {@code SeclumeAws.configure(S3Client.builder(), ...)}
 * does the same by hand.
 */
@AutoConfiguration
@ConditionalOnClass(name = {"space.seclume.aws.SeclumeAws",
        "io.awspring.cloud.autoconfigure.AwsSyncClientCustomizer"})
@ConditionalOnProperty("seclume.aws.access-key-id")
public class SeclumeAwsAutoConfiguration {

    static String spec(Environment environment) {
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
    public AwsAsyncClientCustomizer seclumeAwsAsyncClients(Environment environment) {
        String spec = spec(environment);
        return builder -> configure(builder, spec);
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
