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
 * OpenSSL 3 on 64-bit Linux.
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
        try (SecretProvider secret = provider(keySpec)) {
            return OpenSslPrivateKey.of(NativeKey.read(secret));
        }
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

    /** {@link #keyManager} as a factory - what Netty, Spring's SSL bundles and others take. */
    public static KeyManagerFactory keyManagerFactory(Path chain, String keySpec) {
        return new Factory(keyManager(chain, keySpec));
    }

    /**
     * A TLS context with the key manager and the JVM's default trust - enough
     * for a server; for a client with a certificate, the server it trusts is
     * the JVM's too.
     */
    public static SSLContext sslContext(Path chain, String keySpec) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
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

    private static SecretProvider provider(String keySpec) {
        String spec = keySpec.startsWith("?") ? keySpec.substring(1) : keySpec;
        Map<String, String> options = new LinkedHashMap<>();
        for (String pair : spec.split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                options.put(URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
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
