package space.seclume.tls;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * Client identities named in configuration, built once and kept.
 *
 * <p>Two settings describe one:
 *
 * <pre>
 * clientCert=/etc/tls/client.crt
 * clientKey-provider=file
 * clientKey-path=/etc/tls/client.key
 * </pre>
 *
 * <p>The certificate is a path because it is public and there is nothing to
 * protect. The key is a <b>provider</b>, with its settings under the
 * {@code clientKey-} prefix, so it can arrive from a mounted file, an
 * encrypted blob, an agent socket or anything else that already works for a
 * password - the same prefix convention {@code rds-iam} uses for the AWS key
 * it signs with.
 *
 * <p><b>Why this caches, when almost nothing else in the project does.</b> A
 * {@link P256ClientIdentity} reads the key once and hands it to CNG or
 * OpenSSL, which holds it in native memory for as long as the identity lives.
 * Building one per {@code getConnection} would touch the file, the mount or
 * the token on every physical connect - for a key that does not rotate on
 * that timescale - and would leave a native key handle behind each time,
 * because a URL-built object has nobody to close it. So identities are keyed
 * by the settings that describe them: the same configuration yields the same
 * identity, a pool of fifty connections loads one key, and the key is
 * resident in <b>one</b> place instead of fifty.
 *
 * <p>That makes the cache a deliberate leak of exactly one object per distinct
 * client certificate in the process, which is the same lifetime a
 * {@code KeyManager} built from a keystore has and for the same reason. It is
 * bounded by the configuration, not by traffic.
 *
 * <p>Nothing secret is in a cache key. The settings say <em>where</em> a key
 * comes from and never what it is - {@code SecretProviders} refuses an inline
 * secret outright - so the key is a description of a location.
 */
public final class ClientIdentities {

    private static final Map<String, ClientIdentity> IDENTITIES = new ConcurrentHashMap<>();

    /** The setting naming the certificate chain; its absence means no identity. */
    public static final String CERTIFICATE = "clientCert";

    /** The prefix under which the private key's provider is configured. */
    public static final String KEY_PREFIX = "clientKey-";

    /**
     * A certificate in the Windows certificate store, by SHA-1 thumbprint -
     * the key stays in Windows, or in the TPM; see
     * {@link WindowsStoreClientIdentity}.
     */
    public static final String THUMBPRINT = "clientCertThumbprint";

    /** Which Windows store: {@code CurrentUser} (the default) or {@code LocalMachine}. */
    public static final String STORE = "clientCertStore";

    /** How long a client key file may be unless {@code clientKey-max-length} says otherwise. */
    static final int KEY_MAX_LENGTH = 4096;

    private ClientIdentities() {
    }

    /**
     * The identity these settings describe, or {@code null} for none.
     *
     * @param settings the whole option map - a connection URL's, typically.
     *                 Everything not beginning with {@link #KEY_PREFIX} and
     *                 not {@link #CERTIFICATE} is ignored, so this can be
     *                 handed the same map the password provider gets
     * @throws IllegalArgumentException if a certificate is named without a
     *         key, or the key's provider cannot be built. Silence there would
     *         mean a connection that authenticates with nothing while the
     *         configuration says it does
     */
    public static ClientIdentity of(Map<String, String> settings) {
        String thumbprint = settings.get(THUMBPRINT);
        if (thumbprint != null && !thumbprint.isBlank()) {
            if (settings.get(CERTIFICATE) != null) {
                throw new IllegalArgumentException(CERTIFICATE + " and " + THUMBPRINT + " both "
                        + "name a client certificate - one connection presents one");
            }
            String store = settings.getOrDefault(STORE, "CurrentUser");
            boolean machine = store.equalsIgnoreCase("LocalMachine");
            if (!machine && !store.equalsIgnoreCase("CurrentUser")) {
                throw new IllegalArgumentException(STORE + " is CurrentUser or LocalMachine, not "
                        + store);
            }
            return IDENTITIES.computeIfAbsent("windows " + store.toLowerCase(java.util.Locale.ROOT)
                    + " " + thumbprint.replaceAll("\\s", "").toUpperCase(java.util.Locale.ROOT),
                    ignored -> new WindowsStoreClientIdentity(thumbprint, machine));
        }
        String certificate = settings.get(CERTIFICATE);
        if (certificate == null || certificate.isBlank()) {
            return null;
        }
        Map<String, String> key = nested(settings);
        if (key.isEmpty()) {
            throw new IllegalArgumentException(CERTIFICATE + " names a certificate but nothing "
                    + "says where its private key comes from - add " + KEY_PREFIX + "provider "
                    + "and its settings, for example " + KEY_PREFIX + "provider=file and "
                    + KEY_PREFIX + "path=/etc/tls/client.key");
        }
        // A key file is no password: a P-384 key in PKCS#8 PEM is over 300
        // bytes, past the 256 a secret is held to by default. Unless the
        // settings say otherwise, a key file may be up to 4 KiB.
        // Any spelling the provider would read counts as set - it matches
        // without case or hyphens, and a default under the exact name would
        // win over clientKey-maxlength=8192.
        boolean set = key.keySet().stream()
                .anyMatch(name -> name.replace("-", "").equalsIgnoreCase("maxlength"));
        if (!set) {
            key.put("max-length", String.valueOf(KEY_MAX_LENGTH));
        }
        return IDENTITIES.computeIfAbsent(cacheKey(certificate, key), ignored -> {
            SecretProvider secret = SecretProviders.of(new LinkedHashMap<>(key));
            // Reloading: the certificate on disk is followed, so a rotation
            // is taken up without a restart - see ReloadingClientIdentity.
            return new ReloadingClientIdentity(Path.of(certificate), secret);
        });
    }

    /** The key settings, with the prefix taken off. */
    private static Map<String, String> nested(Map<String, String> settings) {
        Map<String, String> key = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : settings.entrySet()) {
            if (entry.getKey().startsWith(KEY_PREFIX)) {
                key.put(entry.getKey().substring(KEY_PREFIX.length()), entry.getValue());
            }
        }
        return key;
    }

    /**
     * Sorted, so that the same configuration written in a different order is
     * the same identity rather than a second copy of it.
     */
    private static String cacheKey(String certificate, Map<String, String> key) {
        return certificate + "\0" + new TreeMap<>(key);
    }

    /**
     * Closes every identity and empties the cache.
     *
     * <p>For tests and for an application shutting down deliberately. After
     * this the next {@link #of} builds afresh, which is why it is safe to call
     * at any point where no handshake is running.
     */
    public static void closeAll() {
        for (ClientIdentity identity : IDENTITIES.values()) {
            identity.close();
        }
        IDENTITIES.clear();
    }
}
