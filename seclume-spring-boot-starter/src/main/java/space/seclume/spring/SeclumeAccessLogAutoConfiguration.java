package space.seclume.spring;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import space.seclume.audit.AccessLog;
import space.seclume.crypto.PrivateSigningKey;
import space.seclume.secret.KmsSigningKey;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * The access log, from {@code application.properties}:
 *
 * <pre>
 *   seclume.audit.file=/var/log/orders/seclume-access.jsonl
 *   seclume.audit.checkpoint-interval=1m                     # default
 *   seclume.audit.signing-key.kms=aws-kms                    # or vault-transit, gcp-kms, ...
 *   seclume.audit.signing-key.key=alias/orders-audit
 *   seclume.audit.signing-key.region=eu-central-1
 *   seclume.audit.signing-key.credentials=web-identity
 * </pre>
 *
 * <p>or a key the application holds itself, through a provider -
 * {@code seclume.audit.signing-key.provider=file},
 * {@code seclume.audit.signing-key.path=/run/secrets/audit-key.pem}. A KMS
 * key is the better choice: whoever can write the log file cannot then sign
 * for it. Without a signing key the entries are chained and not signed, which
 * proves far less - see {@link AccessLog}.
 *
 * <p>The log is installed for the library's own hooks while the context runs
 * and closed - with a last checkpoint - when it stops. With OpenTelemetry and
 * {@code seclume-opentelemetry} on the class path and an {@code OpenTelemetry}
 * bean, every entry is exported as a log record as well.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "seclume.audit", name = "file")
public class SeclumeAccessLogAutoConfiguration {

    static final String PREFIX = "seclume.audit";

    /** The log and its key, closed together. */
    public static final class SeclumeAccessLog implements AutoCloseable {

        private final AccessLog log;
        private final PrivateSigningKey key;

        SeclumeAccessLog(AccessLog log, PrivateSigningKey key) {
            this.log = log;
            this.key = key;
        }

        /** The log itself - for a sink of one's own. */
        public AccessLog log() {
            return log;
        }

        @Override
        public void close() throws IOException {
            try {
                log.close();
            } finally {
                if (key != null) {
                    key.close();
                }
            }
        }
    }

    @Bean(destroyMethod = "close")
    SeclumeAccessLog seclumeAccessLog(Environment environment) {
        Binder binder = Binder.get(environment);
        Path file = Path.of(environment.getRequiredProperty(PREFIX + ".file"));
        Duration interval = binder.bind(PREFIX + ".checkpoint-interval", Duration.class)
                .orElse(Duration.ofMinutes(1));
        Map<String, String> keySettings = new LinkedHashMap<>(binder.bind(PREFIX + ".signing-key",
                Bindable.mapOf(String.class, String.class)).orElse(Map.of()));
        PrivateSigningKey key = keySettings.isEmpty() ? null : signingKey(keySettings);
        try {
            AccessLog log = AccessLog.open(file, key, interval);
            AccessLog.install(log);
            return new SeclumeAccessLog(log, key);
        } catch (IOException e) {
            if (key != null) {
                key.close();
            }
            throw new UncheckedIOException("the access log " + file + " cannot be opened", e);
        }
    }

    /** A KMS key ({@code kms=...}), or a PEM or DER key through a provider. */
    static PrivateSigningKey signingKey(Map<String, String> settings) {
        if (settings.containsKey("kms")) {
            return KmsSigningKey.of(settings);
        }
        try (SecretScope encoded = SecretScope.fromProvider(SecretProviders.of(settings))) {
            return PrivateSigningKey.decode(encoded.segment(), encoded.length());
        }
    }

    /** Every entry to OpenTelemetry too - only where it is. */
    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"io.opentelemetry.api.OpenTelemetry",
            "space.seclume.opentelemetry.SeclumeAccessLogExporter"})
    static class OpenTelemetryExport {

        @Bean
        Object seclumeAccessLogExport(SeclumeAccessLog log,
                ObjectProvider<io.opentelemetry.api.OpenTelemetry> openTelemetry) {
            io.opentelemetry.api.OpenTelemetry otel = openTelemetry.getIfAvailable();
            if (otel != null) {
                log.log().addSink(space.seclume.opentelemetry.SeclumeAccessLogExporter.of(otel));
            }
            return new Object();
        }
    }
}
