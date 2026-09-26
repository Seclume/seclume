package space.seclume.internal;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest; // seclume-allow: digests of public keys and pins only
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Base64; // seclume-allow: pins are public by design
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import space.seclume.tls.CertificateTrust;

/**
 * Whom one connection trusts, when it is not the JVM's trust store: a CA file
 * of its own ({@code tlsRootCert}), or the server's key itself ({@code tlsPin}).
 *
 * <p><b>The alternative to turning the check off.</b> "PKIX path building
 * failed" is what a server certificate from an internal CA, a cloud
 * provider's CA or a self-signed one gets against the JVM's trust store - and
 * the answer found on the first search result is {@code trustServerCertificate
 * =true}, which encrypts and authenticates nobody. {@code tlsRootCert=/path/ca.pem}
 * names the CA for this connection alone, as libpq's {@code sslrootcert} does,
 * without touching the JVM's store and every other connection with it.
 * {@code tlsPin=sha256/<base64>} goes further: the server's public key is the
 * trust, compared byte for byte - no CA, no chain, no host name - for the
 * self-signed certificate that has no CA to name. The value is what
 * {@code seclume-verify --print-pin} prints, and what curl's
 * {@code --pinnedpubkey} takes.
 *
 * <p>A choice holds for the opens on the thread that made it, like
 * {@link Transports#using} - the option belongs to one connection.
 */
public final class TrustChoice {

    /** The URL option naming a CA file, PEM or DER, one or more certificates. */
    public static final String ROOT_CERT = "tlsRootCert";
    /** The URL option pinning the server's key: {@code sha256/<base64>}. */
    public static final String PIN = "tlsPin";

    private static final ThreadLocal<Choice> CHOSEN = new ThreadLocal<>();

    private TrustChoice() {
    }

    /**
     * One connection's trust.
     *
     * @param rootCert a CA file, or null for the JVM's trust store
     * @param pin      the SHA-256 of the server's public key, or null
     */
    public record Choice(String rootCert, byte[] pin) {
    }

    /**
     * What a URL or its properties choose - the properties winning, as for
     * every option.
     *
     * @return null when neither option is there
     */
    public static Choice of(String url, Properties properties) throws SQLException {
        String root = option(url, properties, ROOT_CERT);
        String pin = option(url, properties, PIN);
        if (root == null && pin == null) {
            return null;
        }
        return new Choice(root, pin == null ? null : parsePin(pin));
    }

    /** Runs an open with {@code choice} for the handshakes on this thread; null changes nothing. */
    public static <T> T using(Choice choice, Transports.Opening<T> opening) throws SQLException {
        if (choice == null) {
            return opening.open();
        }
        Choice before = CHOSEN.get();
        CHOSEN.set(choice);
        try {
            return opening.open();
        } finally {
            if (before == null) {
                CHOSEN.remove();
            } else {
                CHOSEN.set(before);
            }
        }
    }

    /** The choice for a handshake starting on this thread, or null. */
    static Choice current() {
        return CHOSEN.get();
    }

    /** {@code sha256/<base64>} - or {@code sha256//<base64>}, the way curl writes it. */
    static byte[] parsePin(String text) throws SQLException {
        String value = text.trim();
        if (!value.startsWith("sha256/")) {
            throw new SQLException("tlsPin is sha256/<base64 of the key's SHA-256>, and this "
                    + "one is '" + value + "'", "08001");
        }
        value = value.substring(7);
        if (value.startsWith("/")) {
            value = value.substring(1);
        }
        // Base64 has '+', which a URL decoder turns into a blank: the pin is
        // taken as written, and a blank in it can only have been a '+'.
        value = value.replace(' ', '+').replace("%2B", "+").replace("%2b", "+")
                .replace("%2F", "/").replace("%2f", "/").replace("%3D", "=")
                .replace("%3d", "=");
        byte[] pin;
        try {
            pin = Base64.getDecoder().decode(value); // seclume-allow: a pin, public by design
        } catch (IllegalArgumentException e) {
            throw new SQLException("tlsPin is not base64: " + e.getMessage(), "08001");
        }
        if (pin.length != 32) {
            throw new SQLException("tlsPin has " + pin.length + " bytes, a SHA-256 has 32",
                    "08001");
        }
        return pin;
    }

    /** The pin of a certificate's key, as {@code tlsPin} takes it. */
    public static String pinOf(X509Certificate certificate) {
        try {
            return "sha256/" + Base64.getEncoder().encodeToString(MessageDigest // seclume-allow: the digest of a public key
                    .getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded()));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("every JDK has SHA-256", e);
        }
    }

    /** The trust for seclume's own stack: the CA file, or the JVM's store. */
    static CertificateTrust certificateTrust() throws IOException {
        Choice choice = current();
        try {
            return choice == null || choice.rootCert() == null
                    ? CertificateTrust.ofDefaultTrustStore()
                    : CertificateTrust.of(store(choice.rootCert()));
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot read the trust store, so no certificate could be "
                    + "checked: " + e.getMessage(), e);
        }
    }

    /**
     * The JDK's TLS context for the chosen trust - the tlsRootCert, a bundle,
     * or the JVM's store. Public for SQL Server's TDS 7.4 handshake, which
     * runs inside TDS packets and cannot go through TlsLayers.
     */
    public static SSLContext sslContext() throws IOException {
        Choice choice = current();
        try {
            if (choice == null || choice.rootCert() == null) {
                return SSLContext.getDefault();
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            factory.init(store(choice.rootCert()));
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot set up TLS with " + ROOT_CERT + ": " + e.getMessage(),
                    e);
        }
    }

    /** Whether the connection being opened has a tlsPin - which then is the trust. */
    public static boolean pinned() {
        Choice choice = current();
        return choice != null && choice.pin() != null;
    }

    /**
     * After a handshake that checked nothing: the server's key has to be the
     * pinned one, or the connection is closed before a byte of the protocol.
     */
    static void checkPin(TlsLayer layer) throws IOException {
        checkPin(layer.peerCertificate());
    }

    /** The server's certificate against the tlsPin; refused with both named. */
    public static void checkPin(X509Certificate presented) throws IOException {
        Choice choice = current();
        if (presented == null) {
            throw new IOException("the server presented no certificate to compare with tlsPin");
        }
        String got = pinOf(presented);
        String wanted = "sha256/" + Base64.getEncoder().encodeToString(choice.pin()); // seclume-allow: a pin, public by design
        if (!got.equals(wanted)) {                  // both public: nothing to time
            throw new IOException("the server's key is not the pinned one - tlsPin is " + wanted
                    + ", the server presented " + got + " (" + presented
                    .getSubjectX500Principal().getName() + ")");
        }
    }

    /**
     * CA bundles that ship with seclume, named instead of a path:
     * {@code tlsRootCert=aws-rds} is Amazon RDS's global bundle, every region's
     * root and intermediate CAs, and the four Amazon Trust Services roots that
     * an Aurora express cluster's relay and RDS Proxy chain to (found against a
     * live cluster, 26.09.2026). Azure Database chains to a root the JVM
     * already trusts, and Cloud SQL has a CA per instance, so neither needs one.
     */
    static final java.util.Map<String, String> BUNDLES =
            java.util.Map.of("aws-rds", "aws-rds-global-bundle.pem");

    static KeyStore store(String path) throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        int n = 0;
        String bundled = BUNDLES.get(path);
        try (InputStream in = bundled != null ? TrustChoice.class.getResourceAsStream(bundled)
                : Files.newInputStream(Path.of(path))) {
            if (in == null) {
                throw new IOException("the bundled CA file " + bundled + " is missing");
            }
            for (Certificate certificate : CertificateFactory.getInstance("X.509")
                    .generateCertificates(in)) {
                store.setCertificateEntry("root-" + n++, certificate);
            }
        }
        if (n == 0) {
            throw new GeneralSecurityException(path + " holds no certificate");
        }
        return store;
    }

    private static String option(String url, Properties properties, String name) {
        if (properties != null) {
            String value = properties.getProperty(name);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        if (url == null) {
            return null;
        }
        int query = url.indexOf('?');
        if (query < 0) {
            return null;
        }
        int hash = url.indexOf('#', query);
        String options = hash < 0 ? url.substring(query + 1) : url.substring(query + 1, hash);
        for (String pair : options.split("[&;]")) {
            int equals = pair.indexOf('=');
            if (equals > 0 && pair.substring(0, equals).trim().equalsIgnoreCase(name)) {
                String raw = pair.substring(equals + 1);
                // A pin is taken as written (see parsePin); a path may be escaped.
                String value = (name.equals(PIN) ? raw : java.net.URLDecoder.decode(raw,
                        java.nio.charset.StandardCharsets.UTF_8)).trim();
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }
}
