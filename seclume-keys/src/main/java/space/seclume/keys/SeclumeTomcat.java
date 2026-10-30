package space.seclume.keys;

import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;

/**
 * HTTPS on a Tomcat connector with the key in OpenSSL.
 *
 * <p>Tomcat reads its key from a keystore or a PEM file into a
 * {@code PrivateKey} of its own and copies it into an in-memory keystore -
 * a key on the heap twice over. What it also takes is a finished
 * {@code SSLContext} per certificate, and that is what this hands it: one whose
 * key manager is {@link SeclumeKeys#keyManager}.
 *
 * <pre>
 * Connector connector = new Connector();
 * connector.setPort(8443);
 * SeclumeTomcat.enableHttps(connector, Path.of("/etc/tls/chain.pem"),
 *         "provider=file&amp;path=/run/secrets/tls.key");
 * </pre>
 *
 * <p>With Spring Boot, {@code seclume.server.ssl.*} does this for the
 * application's own connector.
 */
public final class SeclumeTomcat {

    private SeclumeTomcat() {
    }

    /** Makes {@code connector} an HTTPS connector serving {@code chain} with the key. */
    public static void enableHttps(Connector connector, Path chain, String keySpec) {
        enable(connector, () -> SeclumeKeys.keyManager(chain, keySpec));
    }

    /**
     * The same, taking up a renewed key and certificate every {@code interval}
     * without a restart - see {@link SeclumeKeys#keyManager(Path, String,
     * java.time.Duration)}.
     */
    public static void enableHttps(Connector connector, Path chain, String keySpec,
                                   java.time.Duration interval) {
        enable(connector, () -> SeclumeKeys.keyManager(chain, keySpec, interval));
    }

    /** Whether the connector asks clients for a certificate. */
    public enum ClientAuth {
        /** It does not. */
        NONE,
        /** It asks, and lets a client without one in. */
        WANT,
        /** A client without a certificate the trust accepts is refused. */
        NEED
    }

    /**
     * HTTPS with a key manager that may keep its own certificate current - one
     * from {@link SeclumeKeys#vaultPkiKeyManager}, from a SPIFFE agent
     * ({@link SeclumeKeys#spiffe}), or a Spring SSL bundle's - so that a
     * renewed certificate is served from the next handshake on, the connector
     * untouched. With {@code trust} and {@code clientAuth} the connector does
     * mutual TLS: a SPIFFE trust manager lets in the workloads of its trust
     * domain, or those its {@code peer-ids} name; {@code null} is the JVM's.
     */
    public static void enableHttps(Connector connector, X509ExtendedKeyManager keys,
                                   javax.net.ssl.X509TrustManager trust, ClientAuth clientAuth) {
        enable(connector, () -> keys, trust, clientAuth);
    }

    private static void enable(Connector connector,
                               java.util.function.Supplier<X509ExtendedKeyManager> managers) {
        enable(connector, managers, null, ClientAuth.NONE);
    }

    private static void enable(Connector connector,
                               java.util.function.Supplier<X509ExtendedKeyManager> managers,
                               javax.net.ssl.X509TrustManager trust, ClientAuth clientAuth) {
        if (!(connector.getProtocolHandler() instanceof AbstractHttp11Protocol<?> protocol)) {
            throw new IllegalArgumentException("HTTPS is set up on an HTTP/1.1 connector, not "
                    + "on " + connector.getProtocolHandler().getClass().getName());
        }
        X509ExtendedKeyManager manager = managers.get();
        javax.net.ssl.SSLContext context;
        try {
            context = javax.net.ssl.SSLContext.getInstance("TLSv1.3");
            context.init(new KeyManager[] {manager},
                    trust == null ? null : new TrustManager[] {trust}, null);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("the TLS context could not be made", e);
        }
        java.security.PrivateKey key = manager.getPrivateKey(SeclumeKeyManager.ALIAS);
        if (key == null) {
            throw new IllegalArgumentException("the key manager has no key under \""
                    + SeclumeKeyManager.ALIAS + "\" - it is not one of seclume-keys'");
        }
        String algorithm = key.getAlgorithm();

        SSLHostConfig host = new SSLHostConfig();
        host.setHostName(protocol.getDefaultSSLHostConfigName());
        host.setCertificateVerification(switch (clientAuth == null ? ClientAuth.NONE
                : clientAuth) {
            case NONE -> "none";
            case WANT -> "optional";
            case NEED -> "required";
        });
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(host,
                algorithm.equals("EC") ? SSLHostConfigCertificate.Type.EC
                        : SSLHostConfigCertificate.Type.RSA);
        certificate.setSslContext(new Provided(context, manager, trust));
        host.addCertificate(certificate);
        protocol.addSslHostConfig(host, true);
        protocol.setSSLEnabled(true);
        connector.setScheme("https");
        connector.setSecure(true);
    }

    /** Tomcat's view of a context that is already initialized. */
    private record Provided(javax.net.ssl.SSLContext context, X509ExtendedKeyManager manager,
                            javax.net.ssl.X509TrustManager trust)
            implements SSLContext {

        @Override
        public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr)
                throws KeyManagementException {
            // made complete by SeclumeTomcat
        }

        @Override
        public void destroy() {
            // the key lives as long as the application
        }

        @Override
        public SSLSessionContext getServerSessionContext() {
            return context.getServerSessionContext();
        }

        @Override
        public SSLEngine createSSLEngine() {
            return context.createSSLEngine();
        }

        @Override
        public SSLServerSocketFactory getServerSocketFactory() {
            return context.getServerSocketFactory();
        }

        @Override
        public SSLParameters getSupportedSSLParameters() {
            return context.getSupportedSSLParameters();
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return manager.getCertificateChain(SeclumeKeyManager.ALIAS);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return trust == null ? new X509Certificate[0] : trust.getAcceptedIssuers();
        }
    }
}
