package space.seclume.inventory;

import java.lang.ref.WeakReference;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import space.seclume.secret.ExpiringCredentials;
import space.seclume.secret.SecretProvider;

/**
 * What cryptography this process uses, as it uses it: every secret read
 * through a provider, every field encryption key ring, every private key,
 * every TLS session and the certificate its server showed - recorded where
 * seclume does the work, so that nothing has to be declared.
 *
 * <p>Facts, never values: a secret is recorded as the kind of provider that
 * read it, where (as the provider describes itself), how often and when, and
 * when it expires; a key as its algorithm and size; a TLS session as its
 * protocol, cipher suite and key exchange. Not a length of a secret, not a
 * fingerprint, not a hash - nothing a short secret could be recovered from.
 *
 * <p>{@link #snapshot()} is the inventory now; {@link CycloneDxCbom} writes it
 * as a CycloneDX 1.6 cryptography bill of materials, each asset with the
 * NIST quantum security level of its algorithm - which of them a quantum
 * computer would break is the question the migration to post-quantum
 * cryptography starts with. The Spring Boot starter serves it at
 * {@code /actuator/cbom}; {@code seclume-verify --cbom} prints one for a
 * connection.
 *
 * <p>Recording is best effort and never in the way: it is called after the
 * work succeeded, it swallows its own failures, and it holds what it records
 * weakly - a provider or a key that is gone drops out. TLS sessions are kept
 * per peer and suite, at most {@value #MAX_SESSIONS} of them.
 */
public final class CryptoInventory {

    /** What an asset is. */
    public enum Kind {
        /** A password, token or other credential a secret provider read. */
        SECRET,
        /** A field encryption data key. */
        DATA_KEY,
        /** A private key that signs - in OpenSSL, CNG or a key management service. */
        PRIVATE_KEY,
        /** A server certificate a TLS handshake was shown. */
        CERTIFICATE,
        /** A TLS session's protocol, cipher suite and key exchange. */
        PROTOCOL
    }

    /**
     * One asset.
     *
     * @param ref       stable within this process: the same asset, the same ref
     * @param algorithm the algorithm by its usual name, or {@code null} for a secret
     * @param bits      the key size, 0 where none applies
     * @param source    where it came from or what holds it - a provider, a peer, a backend
     * @param uses      how often it was read, used or seen
     * @param expires   when it expires, or {@code null}
     * @param facts     more, by name: issuer, cipher suite, key exchange, primary key
     */
    public record Asset(String ref, Kind kind, String name, String algorithm, int bits,
            String source, Instant firstSeen, Instant lastUsed, long uses, Instant expires,
            Map<String, String> facts) {
    }

    /** TLS sessions and certificates kept at most - the oldest are dropped. */
    public static final int MAX_SESSIONS = 512;

    private static final Map<SecretProvider, Seen> SECRETS =
            Collections.synchronizedMap(new java.util.WeakHashMap<>());
    private static final Map<Object, Ring> RINGS =
            Collections.synchronizedMap(new java.util.WeakHashMap<>());
    private static final Map<Object, Key> KEYS =
            Collections.synchronizedMap(new java.util.WeakHashMap<>());
    private static final Map<String, Asset> SESSIONS = new LinkedHashMap<>();

    private CryptoInventory() {
    }

    // ------------------------------------------------------------- recording

    /** A secret was read from {@code provider}. Called by {@code SecretScope}. */
    public static void secretRead(SecretProvider provider) {
        if (provider == null) {
            return;
        }
        try {
            Instant now = Instant.now();
            SECRETS.compute(provider, (ignored, seen) -> seen == null
                    ? new Seen(now, now, 1) : new Seen(seen.first, now, seen.uses + 1));
        } catch (RuntimeException ignored) {
            // an inventory never stands in the way of a login
        }
    }

    /**
     * A field encryption key ring was built.
     *
     * @param ring    the ring, held weakly; {@code closed} says whether it still is one
     * @param sources the kind of provider each key came from, by the key's number
     */
    public static void ring(Object ring, java.util.function.BooleanSupplier closed,
            Map<Integer, String> sources, int primary, String algorithm) {
        try {
            RINGS.put(ring, new Ring(Instant.now(), closed, Map.copyOf(sources), primary,
                    algorithm));
        } catch (RuntimeException ignored) {
            // best effort
        }
    }

    /**
     * A private key was opened.
     *
     * @param key       held weakly
     * @param publicKey its public half, DER, from which algorithm and size are read
     * @param where     what holds it: {@code OpenSSL}, {@code CNG}, a KMS key's description
     */
    public static void privateKey(Object key, byte[] publicKey, String where) {
        if (key == null || publicKey == null || where == null) {
            return;
        }
        try {
            String[] algorithm = algorithmOf(publicKey);
            KEYS.put(key, new Key(Instant.now(), algorithm[0], number(algorithm[1]),
                    where));
        } catch (RuntimeException ignored) {
            // best effort
        }
    }

    /**
     * A TLS handshake finished.
     *
     * @param peer        the server, {@code host} or {@code host:port}
     * @param stack       {@code seclume} or {@code JSSE}
     * @param description protocol and suite, as {@code Secured.tlsDescription} has them
     * @param certificate the server's leaf certificate, or {@code null}
     */
    public static void tls(String peer, String stack, String description,
            X509Certificate certificate) {
        try {
            Instant now = Instant.now();
            Tls parsed = Tls.parse(description);
            Map<String, String> facts = new LinkedHashMap<>();
            facts.put("peer", peer);
            facts.put("stack", stack);
            facts.put("version", parsed.version);
            facts.put("cipherSuite", parsed.suite);
            if (parsed.group != null) {
                facts.put("keyExchange", parsed.group);
            }
            String ref = "protocol:tls:" + peer + ":" + stack + ":" + description;
            synchronized (SESSIONS) {
                seen(ref, Kind.PROTOCOL, "TLS " + parsed.version + " to " + peer,
                        parsed.group == null ? null : parsed.group, 0, stack, now, null, facts);
                if (certificate != null) {
                    certificate(certificate, peer, now);
                }
                while (SESSIONS.size() > MAX_SESSIONS) {
                    String oldest = SESSIONS.values().stream()
                            .min(Comparator.comparing(Asset::lastUsed)).map(Asset::ref)
                            .orElseThrow();
                    SESSIONS.remove(oldest);
                }
            }
        } catch (RuntimeException ignored) {
            // best effort
        }
    }

    private static void certificate(X509Certificate certificate, String peer, Instant now) {
        String[] key = algorithmOf(certificate.getPublicKey().getEncoded());
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("subject", certificate.getSubjectX500Principal().getName());
        facts.put("issuer", certificate.getIssuerX500Principal().getName());
        facts.put("notBefore", certificate.getNotBefore().toInstant().toString());
        facts.put("signatureAlgorithm", certificate.getSigAlgName());
        facts.put("serialNumber", certificate.getSerialNumber().toString(16));
        facts.put("peer", peer);
        String ref = "certificate:" + facts.get("issuer") + ":" + facts.get("serialNumber");
        seen(ref, Kind.CERTIFICATE, facts.get("subject"), key[0], number(key[1]),
                peer, now, certificate.getNotAfter().toInstant(), facts);
    }

    /** A key size as a number, or 0 when it is not one. */
    static int number(String digits) {
        if (digits == null || digits.isEmpty() || digits.length() > 6) {
            return 0;
        }
        int value = 0;
        for (int i = 0; i < digits.length(); i++) {
            char c = digits.charAt(i);
            if (c < '0' || c > '9') {
                return 0;
            }
            value = value * 10 + (c - '0');
        }
        return value;
    }

    private static void seen(String ref, Kind kind, String name, String algorithm, int bits,
            String source, Instant now, Instant expires, Map<String, String> facts) {
        Asset known = SESSIONS.get(ref);
        SESSIONS.put(ref, new Asset(ref, kind, name, algorithm, bits, source,
                known == null ? now : known.firstSeen(), now,
                known == null ? 1 : known.uses() + 1, expires, Map.copyOf(facts)));
    }

    // ------------------------------------------------------------- reporting

    /** Every asset now, secrets first, then keys, then sessions and certificates. */
    public static List<Asset> snapshot() {
        List<Asset> assets = new ArrayList<>();
        Map<String, Integer> numbering = new LinkedHashMap<>();
        for (Map.Entry<SecretProvider, Seen> entry : copy(SECRETS).entrySet()) {
            SecretProvider provider = entry.getKey();
            Seen seen = entry.getValue();
            String kind = kindOf(provider);
            int n = numbering.merge(kind, 1, Integer::sum);
            Map<String, String> facts = new LinkedHashMap<>();
            facts.put("provider", kind);
            facts.put("held", "locked native memory, wiped after use");
            assets.add(new Asset("secret:" + kind + ":" + n, Kind.SECRET, kind + " secret " + n,
                    null, 0, describe(provider), seen.first, seen.last, seen.uses,
                    expiryOf(provider), facts));
        }
        int ringNumber = 0;
        for (Ring ring : copy(RINGS).values()) {
            if (ring.closed.getAsBoolean()) {
                continue;
            }
            ringNumber++;
            for (Map.Entry<Integer, String> key : new java.util.TreeMap<>(ring.sources)
                    .entrySet()) {
                Map<String, String> facts = new LinkedHashMap<>();
                facts.put("ring", Integer.toString(ringNumber));
                facts.put("keyNumber", Integer.toString(key.getKey()));
                facts.put("primary", Boolean.toString(key.getKey() == ring.primary));
                facts.put("held", "locked native memory");
                assets.add(new Asset("data-key:" + ringNumber + ":" + key.getKey(),
                        Kind.DATA_KEY, "field encryption key " + key.getKey(), ring.algorithm,
                        256, key.getValue(), ring.built, ring.built, 1, null, facts));
            }
        }
        int keyNumber = 0;
        for (Key key : copy(KEYS).values()) {
            keyNumber++;
            assets.add(new Asset("private-key:" + keyNumber, Kind.PRIVATE_KEY,
                    key.algorithm + " private key " + keyNumber, key.algorithm, key.bits,
                    key.where, key.opened, key.opened, 1, null, Map.of("held", key.where)));
        }
        synchronized (SESSIONS) {
            assets.addAll(SESSIONS.values());
        }
        return List.copyOf(assets);
    }

    /** Forgets everything - for tests. */
    static void clear() {
        SECRETS.clear();
        RINGS.clear();
        KEYS.clear();
        synchronized (SESSIONS) {
            SESSIONS.clear();
        }
    }

    private static <K, V> Map<K, V> copy(Map<K, V> synchronizedMap) {
        synchronized (synchronizedMap) {
            Map<K, V> copy = new IdentityHashMap<>();
            copy.putAll(synchronizedMap);
            return copy;
        }
    }

    /** {@code VaultSecretProvider} -> {@code vault}, {@code KmsDecryptSecretProvider} -> {@code kms-decrypt}. */
    public static String kindOf(SecretProvider provider) {
        String name = provider.getClass().getSimpleName();
        if (name.isEmpty()) {
            return "callback";
        }
        name = name.replaceAll("SecretProvider$", "");
        return name.replaceAll("([a-z0-9])([A-Z])", "$1-$2").toLowerCase(java.util.Locale.ROOT);
    }

    /** The provider's own description, when it has one - a path, a URL, a key's name. */
    private static String describe(SecretProvider provider) {
        try {
            String said = provider.toString();
            // Object's own toString says nothing - and asking whether it is that one
            // by reflection would be the only reflection in seclume.
            if (said == null || said.equals(provider.getClass().getName() + "@"
                    + Integer.toHexString(System.identityHashCode(provider)))
                    || said.equals(provider.getClass().getName() + "@"
                            + Integer.toHexString(provider.hashCode()))) {
                return kindOf(provider);
            }
            return said.length() > 200 ? said.substring(0, 200) + "..." : said;
        } catch (RuntimeException e) {
            return kindOf(provider);
        }
    }

    /** Asked only now, when somebody wants the inventory - never on the way to a login. */
    private static Instant expiryOf(SecretProvider provider) {
        try {
            return provider instanceof ExpiringCredentials expiring
                    ? expiring.credentialsValidUntil() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Algorithm and size of a public key: {@code RSA}, {@code EC P-256}, {@code Ed25519}... */
    static String[] algorithmOf(byte[] publicKey) {
        for (String type : new String[] {"RSA", "EC", "Ed25519", "Ed448", "ML-DSA", "ML-KEM"}) {
            try {
                PublicKey key = KeyFactory.getInstance(type)
                        .generatePublic(new X509EncodedKeySpec(publicKey));
                if (key instanceof RSAPublicKey rsa) {
                    return new String[] {"RSA", Integer.toString(rsa.getModulus().bitLength())};
                }
                if (key instanceof ECPublicKey ec) {
                    int size = ec.getParams().getCurve().getField().getFieldSize();
                    return new String[] {"EC P-" + (size == 521 ? 521 : size),
                            Integer.toString(size)};
                }
                String name = key instanceof java.security.interfaces.EdECPublicKey ed
                        ? ed.getParams().getName() : key.getAlgorithm();
                return new String[] {name, name.startsWith("Ed25519") ? "255"
                        : name.startsWith("Ed448") ? "448" : "0"};
            } catch (java.security.GeneralSecurityException | RuntimeException notThisType) {
                // try the next
            }
        }
        return new String[] {"unknown", "0"};
    }

    private record Seen(Instant first, Instant last, long uses) {
    }

    private record Ring(Instant built, java.util.function.BooleanSupplier closed,
            Map<Integer, String> sources, int primary, String algorithm) {
    }

    private record Key(Instant opened, String algorithm, int bits, String where) {
    }

    /** {@code TLSv1.3 / TLS_AES_256_GCM_SHA384 with X25519MLKEM768}, taken apart. */
    record Tls(String version, String suite, String group) {

        static Tls parse(String description) {
            String text = description == null ? "" : description.trim();
            int slash = text.indexOf(" / ");
            String version = slash < 0 ? text : text.substring(0, slash).trim();
            String rest = slash < 0 ? "" : text.substring(slash + 3).trim();
            int stackNote = rest.indexOf(" (");
            if (stackNote >= 0) {
                rest = rest.substring(0, stackNote);
            }
            int with = rest.indexOf(" with ");
            String suite = with < 0 ? rest : rest.substring(0, with).trim();
            String group = with < 0 ? null : rest.substring(with + 6).trim();
            return new Tls(version.replace("TLSv", ""), suite, group);
        }
    }
}
