package space.seclume.keys;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;

import space.seclume.secret.KmsSigningKey;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * Private keys that stay out of the JVM - for a TLS server, a client
 * certificate, an SSH login.
 *
 * <p>A key in a Java keystore, a PEM file read by Spring Boot, or anything
 * that becomes a {@code PrivateKey} the usual way, is a set of
 * {@code BigInteger}s on the heap for the life of the application: the one
 * secret in a TLS server whose theft lets anyone be that server. Here the key
 * is read by a secret provider into native memory, decoded by OpenSSL and kept
 * there; Java gets an {@link OpenSslPrivateKey} that holds none of it, and
 * signatures are made by {@link SeclumeKeyProvider}.
 *
 * <pre>
 * // the key's secret provider, as in a seclume JDBC URL
 * String key = "provider=file&amp;path=/run/secrets/tls.key";
 *
 * SSLContext server = SeclumeKeys.sslContext(Path.of("/etc/tls/chain.pem"), key);
 * KeyManagerFactory kmf = SeclumeKeys.keyManagerFactory(Path.of("/etc/tls/chain.pem"), key);
 * KeyPair ssh = SeclumeKeys.keyPair("provider=vault&amp;...");
 * </pre>
 *
 * <p>RSA and EC keys, PEM or DER - PKCS#8, PKCS#1 or SEC 1, without a
 * passphrase (a key encrypted at rest goes through {@code provider=encrypted}).
 * OpenSSL 3 on 64-bit Linux, or CNG on Windows (RSA and EC; Ed25519 with
 * OpenSSL only).
 */
public final class SeclumeKeys {

    private SeclumeKeys() {
    }

    /**
     * The private key named by {@code keySpec} - the secret provider's
     * options, {@code provider=file&path=...} - read once, decoded by OpenSSL.
     * Installs {@link SeclumeKeyProvider}, which signs with it.
     */
    public static PrivateKey privateKey(String keySpec) {
        SeclumeKeyProvider.install();
        Map<String, String> options = options(keySpec);
        if (options.containsKey(KmsSigningKey.KMS)) {
            // A key in a key management service: it signs there, and what is
            // here is its public half and a credential to ask with.
            if (options.containsKey("provider")) {
                throw new IllegalArgumentException("kms= and provider= both say where the key "
                        + "is - in a key management service, or read from a provider; one of "
                        + "them");
            }
            return OpenSslPrivateKey.of(NativeKey.of(KmsSigningKey.of(options)));
        }
        try (SecretProvider secret = provider(keySpec)) {
            return OpenSslPrivateKey.of(NativeKey.read(secret));
        }
    }

    /**
     * The private key {@code secret} writes - PEM or DER - read once and
     * decoded by OpenSSL; for a caller that finds the key inside something
     * else, such as a cloud's service account file. The provider stays the
     * caller's.
     */
    public static PrivateKey privateKey(SecretProvider secret) {
        SeclumeKeyProvider.install();
        return OpenSslPrivateKey.of(NativeKey.read(secret));
    }

    /** The key and its public half - what an SSH client logs in with. */
    public static KeyPair keyPair(String keySpec) {
        OpenSslPrivateKey key = (OpenSslPrivateKey) privateKey(keySpec);
        return new KeyPair(key.nativeKey().publicKey, key);
    }

    /**
     * A key manager with the certificate chain in {@code chain} (PEM, the
     * server's own certificate first) and its key; refuses a chain whose
     * certificate is not the key's.
     */
    public static X509ExtendedKeyManager keyManager(Path chain, String keySpec) {
        X509Certificate[] certificates = certificates(chain);
        OpenSslPrivateKey key = (OpenSslPrivateKey) privateKey(keySpec);
        byte[] expected = key.nativeKey().publicKey.getEncoded();
        if (!Arrays.equals(expected, certificates[0].getPublicKey().getEncoded())) {
            key.destroy();
            throw new IllegalArgumentException("the first certificate in " + chain
                    + " is not the key's - the server's own certificate comes first, then "
                    + "the ones that issued it");
        }
        return new SeclumeKeyManager(certificates, key);
    }

    /**
     * A key manager that takes up a renewed key and certificate without a
     * restart: both are looked at every {@code interval}, and a new pair is
     * used from the next handshake on - if the certificate is the key's. Close
     * it (it is {@code AutoCloseable}) to stop watching.
     */
    public static X509ExtendedKeyManager keyManager(Path chain, String keySpec,
                                                    Duration interval) {
        if (options(keySpec).containsKey(KmsSigningKey.KMS)) {
            throw new IllegalArgumentException("a key in a key management service is not "
                    + "reloaded from disk - leave out the reload interval; the key stays "
                    + "where it is and so does its certificate");
        }
        return new ReloadingKeyManager(chain, keySpec, provider(keySpec), interval);
    }

    /** {@link #keyManager(Path, String, Duration)} as a factory. */
    public static KeyManagerFactory keyManagerFactory(Path chain, String keySpec,
                                                      Duration interval) {
        return new Factory(keyManager(chain, keySpec, interval));
    }

    /** {@link #keyManager} as a factory - what Netty, Spring's SSL bundles and others take. */
    public static KeyManagerFactory keyManagerFactory(Path chain, String keySpec) {
        return new Factory(keyManager(chain, keySpec));
    }

    /**
     * A key manager whose certificate comes from Vault's PKI engine and whose
     * key was generated in OpenSSL - it is never on the heap, never in a file,
     * and Vault never sees it: a P-256 key, a certification request signed
     * with it, and {@code pki/sign/<role>}. Renewed with a new key once two
     * thirds of the certificate's lifetime have passed; close it to stop.
     *
     * <pre>
     * address=https://vault:8200&amp;pki-role=client&amp;common-name=orders.svc
     *   &amp;auth-method=kubernetes&amp;auth-role=orders
     * </pre>
     *
     * <p>{@code pki-mount} ({@code pki}), {@code pki-role}, {@code common-name},
     * and optionally {@code alt-names}, {@code ip-sans}, {@code ttl},
     * {@code renew-at} (0.67), {@code name} (what {@link #managedCertificates()}
     * calls it; the common name by default); the Vault token as {@code provider=vault} takes
     * it - {@code auth-method=kubernetes|jwt|approle|aws|gcp|azure} or the
     * {@code token-} settings - and {@code namespace}, {@code verify},
     * {@code timeout-millis}.
     */
    public static X509ExtendedKeyManager vaultPkiKeyManager(String spec) {
        SeclumeKeyProvider.install();
        return new VaultPkiKeyManager(options(spec), java.time.Clock.systemUTC());
    }

    /**
     * The certificates kept current by key managers that are open - from
     * Vault's PKI, or reloaded from disk - with their validity, when each is
     * to be replaced, and the last failure to replace it: what an endpoint, a
     * health check or a metric shows. Public facts only.
     */
    public static java.util.List<ManagedCertificate> managedCertificates() {
        return RotatingKeyManager.all();
    }

    /**
     * The workload's X.509-SVID from the SPIFFE Workload API as a key manager,
     * its key read into native memory and kept in OpenSSL or CNG - renewed
     * when the agent rotates it. {@code socket=unix:///run/spire/agent.sock}
     * ({@code SPIFFE_ENDPOINT_SOCKET} when left out), {@code timeout-millis}.
     * Close it to stop asking.
     */
    public static X509ExtendedKeyManager spiffeKeyManager(String spec) {
        SeclumeKeyProvider.install();
        Map<String, String> options = options(spec);
        return new SpiffeKeyManager(workloadApi(options), options.get("name"),
                java.time.Clock.systemUTC(), streams(options));
    }

    /**
     * A TLS 1.3 context for mutual TLS between SPIFFE workloads: the SVID as
     * {@link #spiffeKeyManager}, and a peer trusted when its chain leads to the
     * trust bundle the agent gave and - with {@code peer-ids=spiffe://a,spiffe://b}
     * - its SPIFFE ID is one of those. Host names are not checked: an SVID has
     * none.
     */
    public static SSLContext spiffeSslContext(String spec) {
        Spiffe both = spiffe(spec);
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(both.keys().getKeyManagers(), both.trust().getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the TLS context could not be made", e);
        }
    }

    /**
     * The key manager and the trust manager of {@link #spiffeSslContext} as
     * factories, for whatever takes them apart - a Spring SSL bundle, Netty,
     * gRPC. Both share one SVID source.
     */
    public record Spiffe(KeyManagerFactory keys, javax.net.ssl.TrustManagerFactory trust) {
    }

    /** See {@link Spiffe}; {@code name} is what the SVID is listed under. */
    public static Spiffe spiffe(String spec) {
        Map<String, String> options = options(spec);
        SeclumeKeyProvider.install();
        SpiffeKeyManager keys = new SpiffeKeyManager(workloadApi(options), options.get("name"),
                java.time.Clock.systemUTC(), streams(options));
        java.util.Set<String> peers = new java.util.LinkedHashSet<>();
        String named = options.get("peer-ids");
        if (named != null) {
            for (String id : named.split(",")) {
                if (!id.isBlank()) {
                    peers.add(id.trim());
                }
            }
        }
        return new Spiffe(new Factory(keys),
                new TrustFactory(new SpiffeTrustManager(keys::bundleFor, keys::allBundles,
                        peers)));
    }

    /** A {@code TrustManagerFactory} that hands out the one trust manager it was made with. */
    private static final class TrustFactory extends javax.net.ssl.TrustManagerFactory {

        TrustFactory(javax.net.ssl.TrustManager manager) {
            super(new javax.net.ssl.TrustManagerFactorySpi() {
                @Override
                protected void engineInit(KeyStore ks) {
                    // the trust is already there
                }

                @Override
                protected void engineInit(ManagerFactoryParameters spec) {
                    // the trust is already there
                }

                @Override
                protected javax.net.ssl.TrustManager[] engineGetTrustManagers() {
                    return new javax.net.ssl.TrustManager[] {manager};
                }
            }, SeclumeKeyProvider.install(), "SeclumeSpiffe");
        }
    }

    /** {@code stream}: whether the Workload API's stream stays open for rotations - yes by default. */
    private static boolean streams(Map<String, String> options) {
        String value = options.getOrDefault("stream", "true").trim();
        if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
            throw new IllegalArgumentException("stream is true or false, not " + value);
        }
        return Boolean.parseBoolean(value);
    }

    private static space.seclume.secret.SpiffeWorkloadApi workloadApi(
            Map<String, String> options) {
        String socket = options.get("socket");
        return new space.seclume.secret.SpiffeWorkloadApi(socket == null || socket.isBlank()
                ? null : space.seclume.secret.SpiffeWorkloadApi.socketOf(socket),
                space.seclume.secret.SpiffeWorkloadApi.timeoutMillis("timeout-millis",
                        options.get("timeout-millis"), 10_000));
    }

    /** {@link #vaultPkiKeyManager} as a factory. */
    public static KeyManagerFactory vaultPkiKeyManagerFactory(String spec) {
        return new Factory(vaultPkiKeyManager(spec));
    }

    /** A TLS 1.3 client context with {@link #vaultPkiKeyManager} and the JVM's default trust. */
    public static SSLContext vaultPkiSslContext(String spec) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(new KeyManager[] {vaultPkiKeyManager(spec)}, null, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the TLS context could not be made", e);
        }
    }

    /**
     * A TLS context with the key manager and the JVM's default trust - enough
     * for a server; for a client with a certificate, the server it trusts is
     * the JVM's too.
     */
    public static SSLContext sslContext(Path chain, String keySpec) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(new KeyManager[] {keyManager(chain, keySpec)}, null, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the TLS context could not be made", e);
        }
    }

    static X509Certificate[] certificates(Path chain) {
        try (InputStream in = Files.newInputStream(chain)) {
            Collection<? extends Certificate> read =
                    CertificateFactory.getInstance("X.509").generateCertificates(in);
            if (read.isEmpty()) {
                throw new IllegalArgumentException(chain + " holds no certificate");
            }
            return read.stream().map(X509Certificate.class::cast)
                    .toArray(X509Certificate[]::new);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException(chain + " is not a readable PEM certificate "
                    + "chain", e);
        }
    }

    /** {@code name=value&...}, URL-decoded, as a JDBC URL's parameters are. */
    static Map<String, String> options(String spec) {
        String query = spec.startsWith("?") ? spec.substring(1) : spec;
        Map<String, String> options = new LinkedHashMap<>();
        for (String pair : query.split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                options.put(URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
        return options;
    }

    private static SecretProvider provider(String keySpec) {
        Map<String, String> options = options(keySpec);
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no key named: give the secret provider's "
                    + "options, e.g. provider=file&path=/run/secrets/tls.key");
        }
        if (!options.containsKey("max-length") && !options.containsKey("maxLength")) {
            options.put("max-length", "16384");         // a PEM private key
        }
        return SecretProviders.of(options);
    }

    /** A {@code KeyManagerFactory} that hands out the one key manager it was made with. */
    private static final class Factory extends KeyManagerFactory {

        Factory(X509ExtendedKeyManager manager) {
            super(new Spi(manager), SeclumeKeyProvider.install(), "Seclume");
        }
    }

    private static final class Spi extends KeyManagerFactorySpi {

        private final KeyManager[] managers;

        Spi(X509ExtendedKeyManager manager) {
            this.managers = new KeyManager[] {manager};
        }

        @Override
        protected void engineInit(KeyStore ks, char[] password) { // seclume-allow: the JCA signature; no password is taken
            // the key is already there
        }

        @Override
        protected void engineInit(ManagerFactoryParameters spec) {
            // the key is already there
        }

        @Override
        protected KeyManager[] engineGetKeyManagers() {
            return managers.clone();
        }
    }
}
