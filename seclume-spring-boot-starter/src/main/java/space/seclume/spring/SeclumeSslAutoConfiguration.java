package space.seclume.spring;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.GeneralSecurityException;
import java.util.Map;

import javax.net.ssl.TrustManagerFactory;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.ssl.SslBundleRegistrar;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslManagerBundle;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.boot.tomcat.TomcatConnectorCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import space.seclume.keys.SeclumeKeys;
import space.seclume.keys.SeclumeTomcat;

/**
 * TLS keys from {@code application.properties} that stay in OpenSSL:
 *
 * <pre>
 * seclume.ssl.bundles.web.certificate=/etc/tls/chain.pem
 * seclume.ssl.bundles.web.key=provider=file&amp;path=/run/secrets/tls.key
 * seclume.ssl.bundles.web.reload-interval=1m   (a renewed pair, without a restart)
 *
 * seclume.ssl.bundles.client.vault-pki=address=https://vault:8200&amp;pki-role=client\
 *     &amp;common-name=orders.svc&amp;auth-method=kubernetes&amp;auth-role=orders
 *                                        (a key made in OpenSSL, its certificate
 *                                         from Vault's PKI, renewed by itself)
 *
 * seclume.server.ssl.bundle=web          (Tomcat: HTTPS with it)
 * server.ssl.bundle=web                  (Reactor Netty: the same, the Boot way)
 * </pre>
 *
 * <p>Each {@code seclume.ssl.bundles.<name>} becomes a Spring SSL bundle of
 * that name, whose key manager holds the key in OpenSSL (see
 * {@link SeclumeKeys}) and whose trust is the JVM's. Whatever takes a bundle
 * by its managers takes this one: Reactor Netty's server, a {@code RestClient}
 * or {@code WebClient} presenting a client certificate.
 *
 * <p>Tomcat is the exception - Boot hands it the bundle's keystore, and there
 * is none here to hand over. {@code seclume.server.ssl.bundle} sets up HTTPS
 * on Tomcat's connector with the bundle instead ({@link SeclumeTomcat});
 * {@code server.ssl.*} stays unset.
 */
@AutoConfiguration
@ConditionalOnClass(name = {"space.seclume.keys.SeclumeKeys",
        "org.springframework.boot.ssl.SslBundle"})
public class SeclumeSslAutoConfiguration {

    static final String PREFIX = "seclume.ssl.bundles";

    /** One {@code seclume.ssl.bundles.<name>} entry. */
    public static class BundleProperties {

        /** The certificate chain, PEM, the own certificate first. */
        private String certificate;

        /** The private key's secret provider, e.g. provider=file&amp;path=... */
        private String key;

        /**
         * Instead of certificate and key: a key generated in OpenSSL and its
         * certificate from Vault's PKI engine, renewed with a new key before it
         * ends - the settings of {@code SeclumeKeys.vaultPkiKeyManager}.
         */
        private String vaultPki;

        public String getVaultPki() {
            return vaultPki;
        }

        public void setVaultPki(String vaultPki) {
            this.vaultPki = vaultPki;
        }

        /**
         * How often to look whether the key or the certificate was renewed on
         * disk, and serve the new pair from the next handshake on; unset or
         * zero does not look.
         */
        private java.time.Duration reloadInterval;

        public java.time.Duration getReloadInterval() {
            return reloadInterval;
        }

        public void setReloadInterval(java.time.Duration reloadInterval) {
            this.reloadInterval = reloadInterval;
        }

        boolean reloads() {
            return reloadInterval != null && !reloadInterval.isZero();
        }

        public String getCertificate() {
            return certificate;
        }

        public void setCertificate(String certificate) {
            this.certificate = certificate;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }
    }

    static Map<String, BundleProperties> bundles(Environment environment) {
        return Binder.get(environment)
                .bind(PREFIX, Bindable.mapOf(String.class, BundleProperties.class))
                .orElse(Map.of());
    }

    static BundleProperties bundle(Environment environment, String name) {
        BundleProperties bundle = bundles(environment).get(name);
        if (bundle != null && bundle.getVaultPki() != null) {
            if (bundle.getCertificate() != null || bundle.getKey() != null) {
                throw new IllegalStateException(PREFIX + "." + name + " has vault-pki= and "
                        + "certificate= or key=: the certificate comes from one of the two");
            }
            if (bundle.reloads()) {
                throw new IllegalStateException(PREFIX + "." + name + " has vault-pki= and "
                        + "reload-interval=: a certificate from Vault renews itself");
            }
            return bundle;
        }
        if (bundle == null || bundle.getCertificate() == null || bundle.getKey() == null) {
            throw new IllegalStateException("there is no " + PREFIX + "." + name
                    + " with certificate= and key=, or vault-pki=");
        }
        return bundle;
    }

    private static javax.net.ssl.KeyManagerFactory keys(String name,
            BundleProperties properties) {
        if (properties.getVaultPki() != null) {
            return SeclumeKeys.vaultPkiKeyManagerFactory(vaultPkiSpec(name, properties));
        }
        return properties.reloads()
                ? SeclumeKeys.keyManagerFactory(Path.of(properties.getCertificate()),
                        properties.getKey(), properties.getReloadInterval())
                : SeclumeKeys.keyManagerFactory(Path.of(properties.getCertificate()),
                        properties.getKey());
    }

    @Bean
    public SslBundleRegistrar seclumeSslBundles(Environment environment) {
        return registry -> bundles(environment).forEach((name, properties) -> {
            bundle(environment, name);                     // the parts fit together
            registry.registerBundle(name, SslBundle.of(SslStoreBundle.NONE, null, null,
                    SslBundle.DEFAULT_PROTOCOL, SslManagerBundle.of(keys(name, properties),
                            jvmTrust())));
        });
    }

    private static final java.util.regex.Pattern NAME =
            java.util.regex.Pattern.compile("(?:^|&)name=([^&]*)");

    /** The bundle's settings, named after the bundle unless they name themselves. */
    static String vaultPkiSpec(String bundle, BundleProperties properties) {
        String spec = properties.getVaultPki();
        return NAME.matcher(spec).find() ? spec
                : spec + "&name=" + java.net.URLEncoder.encode(bundle,
                        java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * What {@code SeclumeKeys.managedCertificates()} calls each bundle that
     * keeps its certificate current: the bundle - or its own name - for
     * Vault's PKI, the chain file for one reloaded from disk.
     */
    static Map<String, String> managedNames(Environment environment) {
        Map<String, String> names = new java.util.TreeMap<>();
        bundles(environment).forEach((bundle, properties) -> {
            if (properties.getVaultPki() != null) {
                java.util.regex.Matcher named = NAME.matcher(vaultPkiSpec(bundle, properties));
                named.find();
                names.put(bundle, java.net.URLDecoder.decode(named.group(1),
                        java.nio.charset.StandardCharsets.UTF_8));
            } else if (properties.reloads() && properties.getCertificate() != null) {
                names.put(bundle, Path.of(properties.getCertificate()).toString());
            }
        });
        return names;
    }

    /** {@code seclume.certificate.*} meters for those bundles, where Micrometer is. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "io.micrometer.core.instrument.MeterRegistry")
    static class CertificateMetrics {

        @Bean
        SeclumeCertificateMetrics seclumeCertificateMetrics(Environment environment) {
            return new SeclumeCertificateMetrics(managedNames(environment));
        }
    }

    private static TrustManagerFactory jvmTrust() {
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            return factory;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the JVM's trust could not be read", e);
        }
    }

    /** Tomcat's connector, when {@code seclume.server.ssl.bundle} names a bundle. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"org.apache.catalina.connector.Connector",
            "org.springframework.boot.tomcat.TomcatConnectorCustomizer"})
    @ConditionalOnProperty("seclume.server.ssl.bundle")
    static class TomcatHttps {

        @Bean
        TomcatConnectorCustomizer seclumeTomcatHttps(Environment environment) {
            BundleProperties bundle = bundle(environment,
                    environment.getRequiredProperty("seclume.server.ssl.bundle"));
            if (bundle.getVaultPki() != null) {
                throw new IllegalStateException("seclume.server.ssl.bundle names a bundle with "
                        + "vault-pki=, which Tomcat cannot take yet: give it certificate= and "
                        + "key=, or serve with Reactor Netty (server.ssl.bundle)");
            }
            return connector -> {
                if (bundle.reloads()) {
                    SeclumeTomcat.enableHttps(connector, Path.of(bundle.getCertificate()),
                            bundle.getKey(), bundle.getReloadInterval());
                } else {
                    SeclumeTomcat.enableHttps(connector, Path.of(bundle.getCertificate()),
                            bundle.getKey());
                }
            };
        }
    }
}
