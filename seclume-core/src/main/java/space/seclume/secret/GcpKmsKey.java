package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Base64; // seclume-allow: public keys, hashes and signatures
import java.util.List;
import java.util.Map;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A key version in Google Cloud KMS ({@code ASYMMETRIC_SIGN}), signing there:
 * {@code GET .../publicKey} for its public half and algorithm,
 * {@code :asymmetricSign} with the digest made here for each signature.
 *
 * <p>A Cloud KMS key is bound to one algorithm - {@code EC_SIGN_P256_SHA256},
 * {@code RSA_SIGN_PSS_2048_SHA256} - and signs that and nothing else; a
 * request for another hash or padding is refused here with that reason.
 *
 * <p>Settings: {@code key} - the version's resource name,
 * {@code projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>}
 * - and the bearer token under {@code token-} ({@code token-provider=gcp-metadata}
 * on GKE and Compute Engine); optionally {@code endpoint}, {@code verify},
 * {@code timeout-millis}. The principal needs
 * {@code cloudkms.cryptoKeyVersions.viewPublicKey} and {@code .useToSign}.
 */
final class GcpKmsKey implements KmsSigningKey.Service {

    private static final String NAME =
            "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+";

    private final String key;
    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final SecretProvider token;
    private volatile String algorithm = "";

    GcpKmsKey(Map<String, String> settings) {
        this.key = KmsSigningKey.required(settings, "key", "Google Cloud KMS");
        if (!key.matches(NAME)) {
            throw new IllegalArgumentException("key is a key version's resource name, projects/"
                    + "<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>, "
                    + "not " + key);
        }
        String[] endpoint = KmsSigningKey.endpoint(settings.get("endpoint"),
                "cloudkms.googleapis.com");
        this.host = endpoint[0];
        this.port = Integer.parseInt(endpoint[1]);
        this.verify = !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true"));
        this.timeoutMillis = KmsSigningKey.positive(settings, "timeout-millis", 10_000);
        this.token = SecretProviders.bearerToken(settings, "a key in Google Cloud KMS");
    }

    @Override
    public String describe() {
        return "Cloud KMS key " + key;
    }

    @Override
    public byte[] publicKey() throws IOException {
        String answer = call("GET", "/v1/" + key + "/publicKey", null);
        algorithm = field(answer, "algorithm");
        if (!algorithm.startsWith("EC_SIGN_P256") && !algorithm.startsWith("EC_SIGN_P384")
                && !algorithm.startsWith("RSA_SIGN_PSS_") && !algorithm.startsWith("RSA_SIGN_PKCS1_")
                || algorithm.contains("RAW")) {
            throw new IOException("the key's algorithm is " + algorithm + " - EC_SIGN_P256, "
                    + "EC_SIGN_P384 and RSA_SIGN_PSS/PKCS1 with a digest sign for TLS");
        }
        return VaultTransitKey.der(field(answer, "pem"));
    }

    @Override
    public boolean signsPss() {
        return algorithm.startsWith("RSA_SIGN_PSS_");
    }

    @Override
    public byte[] sign(HashAlgorithm digest, boolean pss, byte[] hash) throws IOException {
        String field = switch (digest) {
            case SHA_256 -> "sha256";
            case SHA_384 -> "sha384";
            case SHA_512 -> "sha512";
            default -> throw new IllegalArgumentException("Cloud KMS signs SHA-2 hashes, not "
                    + digest);
        };
        if (!algorithm.endsWith("_" + field.toUpperCase(java.util.Locale.ROOT))) {
            throw new IOException("the key signs " + algorithm + " only, and " + field
                    + " was asked for");
        }
        if (algorithm.startsWith("RSA_") && pss != signsPss()) {
            throw new IOException("the key signs " + algorithm + " only, and "
                    + (pss ? "PSS" : "PKCS#1 v1.5") + " was asked for");
        }
        String answer = call("POST", "/v1/" + key + ":asymmetricSign", "{\"digest\":{\""
                + field + "\":\"" + Base64.getEncoder().encodeToString(hash) // seclume-allow: a public hash
                + "\"}}");
        return Base64.getDecoder().decode(field(answer, "signature")); // seclume-allow: a public signature
    }

    private String call(String method, String path, String body) throws IOException {
        try (Arena arena = Arena.ofConfined();
             SecretScope bearer = SecretScope.fromProvider(token)) {
            MemorySegment answer = arena.allocate(SecretFetch.MAX_RESPONSE);
            SecretFetch.Response response = SecretFetch.send(host, port, verify, timeoutMillis,
                    method, path, body == null ? Map.of()
                            : Map.of("Content-Type", "application/json"),
                    List.of(new SecretFetch.SecretHeader("Authorization",
                            AzureKeyVaultKey.bearer(arena, bearer), 7 + bearer.length())),
                    body, answer);
            // seclume-allow: Cloud KMS's answer about a key - a public key, a signature or an error
            String text = new String(answer.asSlice(0, response.bodyLength())
                    .toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
            if (!response.ok()) {
                throw new IOException("Cloud KMS answered " + response.status() + " to "
                        + method + " " + path + ": " + AzureKeyVaultKey.message(text)
                        + (response.status() == 403 ? " - the principal needs cloudkms."
                                + "cryptoKeyVersions.viewPublicKey and .useToSign" : ""));
            }
            return text;
        }
    }

    private static String field(String answer, String name) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            // seclume-allow: Cloud KMS's answer about a key, which holds no secret
            byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
            MemorySegment json = arena.allocate(Math.max(1, bytes.length));
            MemorySegment.copy(bytes, 0, json, ValueLayout.JAVA_BYTE, 0, bytes.length);
            MemorySegment out = arena.allocate(Math.max(16, bytes.length));
            int written = JsonOff.string(json, bytes.length, out, name);
            // seclume-allow: a public key, a signature or an algorithm's name
            return new String(out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);
        } catch (JsonOff.NotFound e) {
            throw new IOException("Cloud KMS's answer holds no " + name, e);
        }
    }

    @Override
    public void close() {
        token.close();
    }
}
