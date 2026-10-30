package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64; // seclume-allow: public keys, hashes and signatures
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A key in Azure Key Vault or Managed HSM, signing there: {@code GET
 * /keys/<name>} for its public half (a JWK) and its version,
 * {@code POST /keys/<name>/<version>/sign} with the digest made here for each
 * signature - ECDSA answered as r and s, which become DER here.
 *
 * <p>Settings: {@code vault-uri} ({@code https://<vault>.vault.azure.net}),
 * {@code key-name}, optionally {@code key-version} (the current one when it is
 * opened - and then that one, so that a rotation does not part the key from
 * its certificate), and the bearer token under {@code token-}
 * ({@code token-provider=azure-managed-identity&token-resource=https://vault.azure.net});
 * {@code verify}, {@code timeout-millis}. The identity needs the {@code get}
 * and {@code sign} key permissions (Key Vault Crypto User).
 */
final class AzureKeyVaultKey implements KmsSigningKey.Service {

    private static final String API_VERSION = "7.4";
    private static final Pattern ERROR_MESSAGE =
            Pattern.compile("\"message\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    private final String vaultUri;
    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String keyName;
    private final SecretProvider token;
    private volatile String version;
    private volatile boolean ec;

    AzureKeyVaultKey(Map<String, String> settings) {
        this.vaultUri = KmsSigningKey.required(settings, "vault-uri", "Azure Key Vault");
        URI uri = URI.create(vaultUri);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new IllegalArgumentException("the Key Vault address must be https://, not "
                    + vaultUri + " - a bearer token over plain http is a token given away");
        }
        this.host = uri.getHost();
        this.port = uri.getPort() > 0 ? uri.getPort() : 443;
        this.verify = !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true"));
        this.timeoutMillis = KmsSigningKey.positive(settings, "timeout-millis", 10_000);
        this.keyName = SecretNames.require("the key name",
                KmsSigningKey.required(settings, "key-name", "Azure Key Vault"), false);
        String pinned = settings.get("key-version");
        this.version = pinned == null || pinned.isBlank() ? null
                : SecretNames.require("the key version", pinned.trim(), false);
        this.token = SecretProviders.bearerToken(settings, "a key in Azure Key Vault");
    }

    @Override
    public String describe() {
        String now = version;
        return "Key Vault key " + keyName + (now == null ? "" : " version " + now) + " in "
                + vaultUri;
    }

    @Override
    public byte[] publicKey() throws IOException {
        String path = "/keys/" + keyName + (version == null ? "" : "/" + version)
                + "?api-version=" + API_VERSION;
        String answer = call("GET", path, null);
        String kid = field(answer, "key", "kid");
        int slash = kid.lastIndexOf('/');
        if (slash < 0 || slash == kid.length() - 1) {
            throw new IOException("Key Vault's kid " + kid + " names no version");
        }
        if (version == null) {
            version = SecretNames.require("the key version", kid.substring(slash + 1), false);
        }
        String kty = field(answer, "key", "kty");
        try {
            if (kty.startsWith("EC")) {
                ec = true;
                String curve = switch (field(answer, "key", "crv")) {
                    case "P-256" -> "secp256r1";
                    case "P-384" -> "secp384r1";
                    default -> throw new IOException("the key's curve is "
                            + field(answer, "key", "crv") + " - P-256 and P-384 sign for TLS");
                };
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(curve));
                ECPoint point = new ECPoint(unsigned(field(answer, "key", "x")),
                        unsigned(field(answer, "key", "y")));
                return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point,
                        parameters.getParameterSpec(ECParameterSpec.class))).getEncoded();
            }
            if (kty.startsWith("RSA")) {
                ec = false;
                return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                        unsigned(field(answer, "key", "n")), unsigned(field(answer, "key", "e"))))
                        .getEncoded();
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Key Vault's public key could not be read: " + e.getMessage(),
                    e);
        }
        throw new IOException("the key is of type " + kty + " - EC and RSA keys sign for TLS");
    }

    /** A JWK's base64url number, public: a coordinate, a modulus, an exponent. */
    private static java.math.BigInteger unsigned(String base64url) { // seclume-allow: a public key's numbers
        return new java.math.BigInteger(1, Base64.getUrlDecoder().decode(base64url)); // seclume-allow: a public key's numbers
    }

    @Override
    public byte[] sign(HashAlgorithm digest, boolean pss, byte[] hash) throws IOException {
        String bits = switch (digest) {
            case SHA_256 -> "256";
            case SHA_384 -> "384";
            case SHA_512 -> "512";
            default -> throw new IllegalArgumentException("Key Vault signs SHA-2 hashes, not "
                    + digest);
        };
        String algorithm = (ec ? "ES" : pss ? "PS" : "RS") + bits;
        String answer = call("POST", "/keys/" + keyName + "/" + version + "/sign?api-version="
                + API_VERSION, "{\"alg\":\"" + algorithm + "\",\"value\":\""
                + Base64.getUrlEncoder().withoutPadding().encodeToString(hash) // seclume-allow: a public hash
                + "\"}");
        byte[] signature = Base64.getUrlDecoder().decode(field(answer, "value")); // seclume-allow: a public signature
        return ec ? KmsSigningKey.derFromRaw(signature) : signature;
    }

    private String call(String method, String path, String body) throws IOException {
        try (Arena arena = Arena.ofConfined();
             SecretScope bearer = SecretScope.fromProvider(token)) {
            MemorySegment answer = arena.allocate(SecretFetch.MAX_RESPONSE);
            SecretFetch.Response response = SecretFetch.send(host, port, verify, timeoutMillis,
                    method, path, body == null ? Map.of()
                            : Map.of("Content-Type", "application/json"),
                    List.of(new SecretFetch.SecretHeader("Authorization", bearer(arena, bearer),
                            7 + bearer.length())),
                    body, answer);
            // seclume-allow: Key Vault's answer about a key - a public key, a signature or an error
            String text = new String(answer.asSlice(0, response.bodyLength())
                    .toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
            if (!response.ok()) {
                throw new IOException("Key Vault answered " + response.status() + " to "
                        + method + " " + path.substring(0, path.indexOf('?')) + ": "
                        + message(text) + (response.status() == 403 ? " - the identity needs "
                                + "the get and sign key permissions" : ""));
            }
            return text;
        }
    }

    /** The {@code message} of an error answer, which is public text. */
    static String message(String text) {
        Matcher message = ERROR_MESSAGE.matcher(text);
        if (!message.find()) {
            return "no reason given";
        }
        String said = message.group(1);
        return said.length() > 300 ? said.substring(0, 300) + "..." : said;
    }

    /** {@code Bearer } and the token, joined in native memory. */
    static MemorySegment bearer(Arena arena, SecretScope bearer) {
        MemorySegment value = arena.allocate(7L + bearer.length());
        byte[] word = {'B', 'e', 'a', 'r', 'e', 'r', ' '}; // seclume-allow: a constant word, not a secret
        MemorySegment.copy(word, 0, value, ValueLayout.JAVA_BYTE, 0, 7);
        MemorySegment.copy(bearer.segment(), 0, value, 7, bearer.length());
        return value;
    }

    private static String field(String answer, String... path) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            // seclume-allow: Key Vault's answer about a key, which holds no secret
            byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
            MemorySegment json = arena.allocate(Math.max(1, bytes.length));
            MemorySegment.copy(bytes, 0, json, ValueLayout.JAVA_BYTE, 0, bytes.length);
            MemorySegment out = arena.allocate(Math.max(16, bytes.length));
            int written = JsonOff.string(json, bytes.length, out, path);
            // seclume-allow: a public key's field, a signature or a key's type
            return new String(out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);
        } catch (JsonOff.NotFound e) {
            throw new IOException("Key Vault's answer holds no " + String.join(".", path), e);
        }
    }

    @Override
    public void close() {
        token.close();
    }
}
