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

    /**
     * A certificate in the Windows store by subject - a whole one
     * ({@code CN=app1, O=Example}) or a common name - instead of a thumbprint:
     * the newest valid one, and a renewed one taken up without a restart.
     */
    public static final String SUBJECT = "clientCertSubject";

    /** A PKCS#11 module whose token holds the key - see {@link Pkcs11ClientIdentity}. */
    public static final String PKCS11 = "clientCertPkcs11";

    /** The token's label; without it, the first token. */
    public static final String PKCS11_TOKEN = "clientCertPkcs11Token";

    /** The label of the key, and of the certificate, on the token. */
    public static final String PKCS11_KEY = "clientCertPkcs11Key";

    /** The prefix under which the token PIN's provider is configured. */
    public static final String PIN_PREFIX = "clientCertPin-";

    /**
     * Settings of a client certificate from Vault's PKI for a key generated in
     * native memory - {@code clientCertVaultPki-address},
     * {@code clientCertVaultPki-pki-role}, {@code clientCertVaultPki-common-name},
     * the Vault login as for {@code provider=vault}, and the rest of
     * {@link space.seclume.secret.VaultPkiIssuer}'s settings - renewed by
     * itself before it ends.
     */
    public static final String VAULT_PKI_PREFIX = "clientCertVaultPki-";

    /**
     * The workload's X.509-SVID from the SPIFFE Workload API as the client
     * certificate: the agent's socket ({@code unix:///run/spire/agent.sock}),
     * or {@code true} for the one {@code SPIFFE_ENDPOINT_SOCKET} names.
     */
    public static final String SPIFFE = "clientCertSpiffe";

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
        String spiffe = settings.get(SPIFFE);
        if (spiffe != null && !spiffe.isBlank()) {
            for (String other : new String[] {CERTIFICATE, THUMBPRINT, SUBJECT, PKCS11}) {
                String value = settings.get(other);
                if (value != null && !value.isBlank()) {
                    throw new IllegalArgumentException(SPIFFE + " presents the workload's SVID, "
                            + "and " + other + " names another certificate - one connection "
                            + "presents one");
                }
            }
            if (!nested(settings, VAULT_PKI_PREFIX).isEmpty()) {
                throw new IllegalArgumentException(SPIFFE + " and " + VAULT_PKI_PREFIX
                        + " settings both get a client certificate - one connection presents "
                        + "one");
            }
            String where = spiffe.trim();
            java.nio.file.Path socket = where.equalsIgnoreCase("true") ? null
                    : space.seclume.secret.SpiffeWorkloadApi.socketOf(where);
            int timeout = space.seclume.secret.SpiffeWorkloadApi.timeoutMillis(
                    SPIFFE + "-timeout-millis", settings.get(SPIFFE + "-timeout-millis"), 10_000);
            return IDENTITIES.computeIfAbsent("spiffe " + where.toLowerCase(java.util.Locale.ROOT),
                    ignored -> new SpiffeClientIdentity(new space.seclume.secret.SpiffeWorkloadApi(
                            socket, timeout), java.time.Clock.systemUTC()));
        }
        Map<String, String> vault = nested(settings, VAULT_PKI_PREFIX);
        if (!vault.isEmpty()) {
            for (String other : new String[] {CERTIFICATE, THUMBPRINT, SUBJECT, PKCS11}) {
                String value = settings.get(other);
                if (value != null && !value.isBlank()) {
                    throw new IllegalArgumentException(VAULT_PKI_PREFIX + " settings get a "
                            + "client certificate from Vault, and so does " + other
                            + " name one - one connection presents one");
                }
            }
            return IDENTITIES.computeIfAbsent("vault-pki " + new TreeMap<>(vault),
                    ignored -> new VaultPkiClientIdentity(vault, java.time.Clock.systemUTC()));
        }
        String module = settings.get(PKCS11);
        if (module != null && !module.isBlank()) {
            if (settings.get(THUMBPRINT) != null || settings.get(SUBJECT) != null) {
                throw new IllegalArgumentException(PKCS11 + " names a client certificate's key, "
                        + "and so does the Windows store - one connection presents one");
            }
            Map<String, String> pin = nested(settings, PIN_PREFIX);
            String certificate = settings.get(CERTIFICATE);
            String token = settings.get(PKCS11_TOKEN);
            String label = settings.get(PKCS11_KEY);
            return IDENTITIES.computeIfAbsent("pkcs11 " + module + "\0" + token + "\0" + label
                    + "\0" + certificate + "\0" + new TreeMap<>(pin), ignored ->
                    new Pkcs11ClientIdentity(module, token, label,
                            pin.isEmpty() ? null : SecretProviders.of(new LinkedHashMap<>(pin)),
                            certificate == null || certificate.isBlank() ? null
                                    : Path.of(certificate)));
        }
        String subject = settings.get(SUBJECT);
        if (subject != null && !subject.isBlank()) {
            if (settings.get(CERTIFICATE) != null || settings.get(THUMBPRINT) != null) {
                throw new IllegalArgumentException(SUBJECT + " names a client certificate, and "
                        + "so does " + (settings.get(CERTIFICATE) != null ? CERTIFICATE
                        : THUMBPRINT) + " - one connection presents one");
            }
            boolean machine = machine(settings);
            return IDENTITIES.computeIfAbsent("windows-subject " + machine + " "
                    + subject.trim().toLowerCase(java.util.Locale.ROOT),
                    ignored -> new RenewingStoreClientIdentity(subject.trim(), machine));
        }
        String thumbprint = settings.get(THUMBPRINT);
        if (thumbprint != null && !thumbprint.isBlank()) {
            if (settings.get(CERTIFICATE) != null) {
                throw new IllegalArgumentException(CERTIFICATE + " and " + THUMBPRINT + " both "
                        + "name a client certificate - one connection presents one");
            }
            String store = settings.getOrDefault(STORE, "CurrentUser");
            boolean machine = machine(settings);
            return IDENTITIES.computeIfAbsent("windows " + store.toLowerCase(java.util.Locale.ROOT)
                    + " " + thumbprint.replaceAll("\\s", "").toUpperCase(java.util.Locale.ROOT),
                    ignored -> new WindowsStoreClientIdentity(thumbprint, machine));
        }
        String certificate = settings.get(CERTIFICATE);
        if (certificate == null || certificate.isBlank()) {
            return null;
        }
        Map<String, String> key = nested(settings, KEY_PREFIX);
        if (key.containsKey(space.seclume.secret.KmsSigningKey.KMS)) {
            if (key.containsKey("provider")) {
                throw new IllegalArgumentException(KEY_PREFIX + "kms and " + KEY_PREFIX
                        + "provider both say where the key is - in a key management service, "
                        + "or read from a provider; one of them");
            }
            return IDENTITIES.computeIfAbsent("kms " + cacheKey(certificate, key),
                    ignored -> kmsIdentity(Path.of(certificate), key));
        }
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

    /**
     * The certificate in {@code chain} and its key in a key management
     * service, which signs each handshake there - checked to be the
     * certificate's key before anything connects.
     */
    private static ClientIdentity kmsIdentity(Path chain, Map<String, String> key) {
        java.util.List<java.security.cert.X509Certificate> certificates =
                new java.util.ArrayList<>();
        try {
            java.security.cert.CertificateFactory factory =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            for (byte[] der : EcClientIdentity.parseChain(
                    java.nio.file.Files.readAllBytes(chain), chain)) { // seclume-allow: a certificate chain, public
                certificates.add((java.security.cert.X509Certificate) factory.generateCertificate(
                        new java.io.ByteArrayInputStream(der)));
            }
        } catch (java.io.IOException | java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException("the client certificate " + chain
                    + " could not be read: " + e.getMessage(), e);
        }
        space.seclume.secret.KmsSigningKey remote = space.seclume.secret.KmsSigningKey.of(
                new LinkedHashMap<>(key));
        if (!java.util.Arrays.equals(remote.publicKey(),
                certificates.get(0).getPublicKey().getEncoded())) {
            String name = remote.name();
            remote.close();
            throw new IllegalArgumentException("the first certificate in " + chain + " is not "
                    + "the key's - " + name + " has another public key");
        }
        return new RenewingClientIdentity.Generation(certificates, remote);
    }

    /** {@code clientCertStore}: LocalMachine, or CurrentUser - the default. */
    private static boolean machine(Map<String, String> settings) {
        String store = settings.getOrDefault(STORE, "CurrentUser");
        boolean machine = store.equalsIgnoreCase("LocalMachine");
        if (!machine && !store.equalsIgnoreCase("CurrentUser")) {
            throw new IllegalArgumentException(STORE + " is CurrentUser or LocalMachine, not "
                    + store);
        }
        return machine;
    }

    /** The key settings, with the prefix taken off. */
    private static Map<String, String> nested(Map<String, String> settings, String prefix) {
        Map<String, String> key = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : settings.entrySet()) {
            if (entry.getKey().startsWith(prefix)) {
                key.put(entry.getKey().substring(prefix.length()), entry.getValue());
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
