package space.seclume.kafka;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.sql.SQLException;
import java.util.Base64; // seclume-allow: encoding CA certificates - public
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;

import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.common.security.auth.SslEngineFactory;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.internal.TrustChoice;

/**
 * Kafka's TLS on seclume's own TLS 1.3 stack - and the place where the
 * PLAIN password and the OAUTHBEARER token enter the connection:
 *
 * <pre>
 * security.protocol=SASL_SSL
 * ssl.engine.factory.class=space.seclume.kafka.SeclumeSslEngineFactory
 * sasl.mechanism=PLAIN
 * sasl.jaas.config=space.seclume.kafka.SeclumePlainLoginModule required \
 *     username="orders" provider="file" path="/run/secrets/kafka";
 * </pre>
 *
 * <p>With the JDK's engine the SASL message - the password itself for PLAIN,
 * the token for OAUTHBEARER - passes through Kafka's request buffers and then
 * through JSSE's, all of them heap, none of them wiped. The login modules of
 * this package give Kafka a placeholder instead, and the engine made here
 * writes the secret, from native memory, into the SaslAuthenticate request as
 * it is encrypted (see {@link SaslAuthenticateRewriter}). SCRAM needs none of
 * this, and works over it as well.
 *
 * <p>The broker's certificate is always checked, its host name included:
 * against {@code ssl.truststore.location} (PEM, JKS or PKCS12) or
 * {@code ssl.truststore.certificates} when given, else against the JVM's trust
 * store; {@code seclume.tls.pin=sha256/...} pins the broker's key instead.
 * TLS 1.3 only. Client certificates ({@code ssl.keystore.*}) are refused.
 */
public final class SeclumeSslEngineFactory implements SslEngineFactory {

    /** The broker's key, pinned: {@code sha256/<base64>}, as {@code tlsPin} takes it. */
    public static final String PIN = "seclume.tls.pin";

    private static final AtomicBoolean CONFIGURED = new AtomicBoolean();

    private TrustChoice.Choice trust;
    private Path madeTrustFile;

    /** For Kafka, which makes one per client from its class name. */
    public SeclumeSslEngineFactory() {
    }

    /** Whether any Kafka client in this JVM encrypts through this factory. */
    static boolean configured() {
        return CONFIGURED.get();
    }

    @Override
    public void configure(Map<String, ?> configs) {
        String identification = string(configs, "ssl.endpoint.identification.algorithm");
        if (identification != null && identification.isEmpty()) {
            throw new IllegalArgumentException("ssl.endpoint.identification.algorithm is empty, "
                    + "which turns the check of the broker's host name off. seclume always "
                    + "checks it - a certificate for another name would get the secret");
        }
        for (String key : new String[] {"ssl.keystore.location", "ssl.keystore.key",
                "ssl.keystore.certificate.chain"}) {
            if (configs.get(key) != null) {
                throw new IllegalArgumentException(key + " is set: client certificates do not "
                        + "go through SeclumeSslEngineFactory yet - its private key would be "
                        + "read by the JDK onto the heap");
            }
        }
        String rootCert = trustFile(configs);
        String pin = string(configs, PIN);
        if (rootCert != null || pin != null) {
            Properties named = new Properties();
            if (rootCert != null) {
                named.setProperty(TrustChoice.ROOT_CERT, rootCert);
            }
            if (pin != null) {
                named.setProperty(TrustChoice.PIN, pin);
            }
            try {
                trust = TrustChoice.of(null, named);
            } catch (SQLException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
        CONFIGURED.set(true);
    }

    @Override
    public SSLEngine createClientSslEngine(String peerHost, int peerPort,
                                           String endpointIdentification) {
        return new SeclumeSslEngine(peerHost, peerPort, trust, new SaslAuthenticateRewriter());
    }

    @Override
    public SSLEngine createServerSslEngine(String peerHost, int peerPort) {
        throw new UnsupportedOperationException("SeclumeSslEngineFactory is for Kafka clients; "
                + "a broker keeps its own TLS");
    }

    @Override
    public boolean shouldBeRebuilt(Map<String, Object> nextConfigs) {
        return false;
    }

    @Override
    public Set<String> reconfigurableConfigs() {
        return Set.of();
    }

    @Override
    public KeyStore keystore() {
        return null;
    }

    @Override
    public KeyStore truststore() {
        return null;
    }

    @Override
    public void close() {
        if (madeTrustFile != null) {
            try {
                Files.deleteIfExists(madeTrustFile);
            } catch (IOException ignored) {
                // a temporary file of public certificates
            }
        }
    }

    /**
     * The trust store as a file of PEM certificates, which is what
     * {@code tlsRootCert} reads: a PEM file as it is, a JKS or PKCS12 store
     * and inline certificates written out - CA certificates, public.
     */
    private String trustFile(Map<String, ?> configs) {
        String type = string(configs, "ssl.truststore.type");
        String location = string(configs, "ssl.truststore.location");
        Object inline = configs.get("ssl.truststore.certificates");
        if (inline != null) {
            return write(inline instanceof Password p ? p.value() : inline.toString());
        }
        if (location == null) {
            return null;
        }
        if (type == null || type.equalsIgnoreCase("PEM")) {
            return location;
        }
        Object password = configs.get("ssl.truststore.password");
        char[] storePassword = password == null ? null // seclume-allow: a trust store's integrity password, which Kafka's configuration holds as a String anyway
                : (password instanceof Password p ? p.value() : password.toString()).toCharArray();
        try (InputStream in = Files.newInputStream(Path.of(location))) {
            KeyStore store = KeyStore.getInstance(type.toUpperCase(Locale.ROOT));
            store.load(in, storePassword);
            StringBuilder pem = new StringBuilder();
            for (String alias : Collections.list(store.aliases())) {
                Certificate certificate = store.getCertificate(alias);
                if (certificate != null) {
                    pem.append("-----BEGIN CERTIFICATE-----\n")
                            .append(Base64.getMimeEncoder(64, new byte[] {'\n'}) // seclume-allow: a CA certificate - public
                                    .encodeToString(certificate.getEncoded()))
                            .append("\n-----END CERTIFICATE-----\n");
                }
            }
            if (pem.isEmpty()) {
                throw new IllegalArgumentException(location + " holds no certificate");
            }
            return write(pem.toString());
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException("cannot read the trust store " + location + ": "
                    + e.getMessage(), e);
        } finally {
            if (storePassword != null) {
                java.util.Arrays.fill(storePassword, '\0');
            }
        }
    }

    private String write(String pem) {
        try {
            madeTrustFile = Files.createTempFile("seclume-kafka-trust", ".pem");
            madeTrustFile.toFile().deleteOnExit();
            Files.writeString(madeTrustFile, pem, StandardCharsets.US_ASCII);
            return madeTrustFile.toString();
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot write the trusted certificates out: "
                    + e.getMessage(), e);
        }
    }

    private static String string(Map<String, ?> configs, String key) {
        Object value = configs.get(key);
        return value == null ? null : value.toString().trim();
    }
}
