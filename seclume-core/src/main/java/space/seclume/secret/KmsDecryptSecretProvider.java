package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import space.seclume.internal.Base64Off;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A secret a cloud key management service encrypted, decrypted there on every
 * read: {@code provider=kms-decrypt} with {@code kms=} naming the service, as
 * for signing keys ({@link KmsSigningKey}).
 *
 * <ul>
 * <li>{@code kms=aws-kms}: {@code TrentService.Decrypt} with the
 *     {@code CiphertextBlob} {@code aws kms encrypt} or
 *     {@code GenerateDataKeyWithoutPlaintext} handed out; settings {@code key}
 *     (the key's ARN or alias, so that a ciphertext of another key is
 *     refused), {@code region}, and the credentials as for signing
 *     ({@code credentials=instance|container|web-identity}, or
 *     {@code access-key-id} with {@code key-provider}). Needs
 *     {@code kms:Decrypt}.</li>
 * <li>{@code kms=gcp-kms}: {@code POST /v1/<key>:decrypt}; {@code key} is the
 *     crypto key's resource name, {@code projects/.../cryptoKeys/<k>}, the
 *     bearer token from {@code token-provider}. Needs
 *     {@code cloudkms.cryptoKeyVersions.useToDecrypt}.</li>
 * <li>{@code kms=azure-key-vault}: {@code POST /keys/<name>/<version>/unwrapkey}
 *     with {@code algorithm} ({@code RSA-OAEP-256} by default) on an RSA key;
 *     settings {@code vault-uri}, {@code key-name}, {@code key-version}, the
 *     bearer token from {@code token-provider}. Needs the {@code unwrapKey}
 *     key permission.</li>
 * <li>{@code kms=vault-transit}: the same as {@code provider=vault-transit}.</li>
 * </ul>
 *
 * <p>{@code ciphertext} is the Base64 (for Azure, also Base64url) the service
 * handed out, and no secret: only the service opens it. Each answer carries the
 * plaintext in Base64 inside JSON; both are read in native memory and decoded
 * into the target, so the secret is never a Java object. The envelope for field
 * encryption's data keys ({@code space.seclume.field.FieldKeys}), read once
 * when the key ring is built.
 */
public final class KmsDecryptSecretProvider implements SecretProvider {

    private static final String AWS_TARGET = "TrentService.Decrypt";

    private final Service service;
    private final int maxLength;

    /** One service's request and the field of its answer that holds the plaintext. */
    private interface Service extends AutoCloseable {

        /** Sends the request; the answer into {@code answer}. */
        SecretFetch.Response send(MemorySegment answer) throws IOException;

        /** The JSON path of the plaintext in a successful answer. */
        String[] field();

        /** What the refusal of {@code status} means, beyond the service's own words. */
        String hint(int status);

        /** The service's own words about a refusal - public text. */
        String reason(MemorySegment answer, int length);

        String describe();

        @Override
        void close();
    }

    private KmsDecryptSecretProvider(Service service, int maxLength) {
        this.service = service;
        this.maxLength = maxLength;
    }

    /** From {@code kms=} and the service's settings; {@code vault-transit} is its own class. */
    static SecretProvider of(Map<String, String> settings, int maxLength) {
        String kms = settings.get(KmsSigningKey.KMS);
        if (kms == null || kms.isBlank()) {
            throw new IllegalArgumentException("provider=kms-decrypt needs kms=aws-kms, gcp-kms, "
                    + "azure-key-vault or vault-transit");
        }
        String ciphertext = settings.get("ciphertext");
        if (ciphertext == null || ciphertext.isBlank()) {
            throw new IllegalArgumentException("provider=kms-decrypt needs ciphertext: the "
                    + "Base64 the key management service handed out");
        }
        return switch (kms.trim().toLowerCase(Locale.ROOT)) {
            case "aws-kms" -> new KmsDecryptSecretProvider(new Aws(settings, base64(ciphertext,
                    false)), maxLength);
            case "gcp-kms" -> new KmsDecryptSecretProvider(new Gcp(settings, base64(ciphertext,
                    false)), maxLength);
            case "azure-key-vault" -> new KmsDecryptSecretProvider(new Azure(settings,
                    base64(ciphertext, true)), maxLength);
            case "vault-transit" -> new VaultTransitSecretProvider(settings, maxLength);
            default -> throw new IllegalArgumentException("unknown kms '" + kms
                    + "' - known are aws-kms, gcp-kms, azure-key-vault, vault-transit");
        };
    }

    /** The ciphertext as given, checked to be Base64 - it goes into a JSON string as it is. */
    private static String base64(String value, boolean url) {
        String trimmed = value.trim();
        if (!trimmed.matches(url ? "[A-Za-z0-9+/_-]+={0,2}" : "[A-Za-z0-9+/]+={0,2}")) {
            throw new IllegalArgumentException("ciphertext is Base64" + (url ? " or Base64url"
                    : "") + ", as the service handed it out");
        }
        return trimmed;
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE);
             SecretScope encoded = SecretScope.in(arena,
                     Math.max(64, Base64Off.encodedLength(maxLength) + 4))) {
            SecretFetch.Response response = service.send(answer.segment());
            answer.length(response.bodyLength());
            if (!response.ok()) {
                throw new SecretUnavailableException(service.describe() + " answered "
                        + response.status() + ": " + service.reason(answer.segment(),
                                response.bodyLength()) + service.hint(response.status()));
            }
            int length;
            try {
                length = JsonOff.string(answer.segment(), answer.length(), encoded.segment(),
                        service.field());
            } catch (JsonOff.NotFound e) {
                if (e.getMessage() != null && e.getMessage().contains("longer than the space")) {
                    throw new SecretUnavailableException("the decrypted secret is longer than "
                            + maxLength + " bytes - raise max-length", e);
                }
                throw new SecretUnavailableException(service.describe() + "'s answer holds no "
                        + String.join(".", service.field()) + ": " + e.getMessage(), e);
            }
            fromUrlAlphabet(encoded.segment(), length);
            try (SecretScope raw = SecretScope.in(arena,
                    Math.max(1, Base64Off.decodedUpperBound(length)))) {
                int decoded;
                try {
                    decoded = Base64Off.decode(encoded.segment(), 0, length, raw.segment(), 0);
                } catch (IllegalArgumentException notBase64) {
                    throw new SecretUnavailableException(service.describe()
                            + "'s plaintext is not Base64", notBase64);
                }
                if (decoded > target.byteSize()) {
                    throw new SecretUnavailableException("the decrypted secret is " + decoded
                            + " bytes and does not fit into the " + target.byteSize()
                            + " bytes provided - raise max-length");
                }
                MemorySegment.copy(raw.segment(), 0, target, 0, decoded);
                return decoded;
            }
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot reach " + service.describe() + ": "
                    + e.getMessage(), e);
        }
    }

    /**
     * Base64url's {@code -} and {@code _} as {@code +} and {@code /}, in place
     * and without a branch on the characters - they are the secret's encoding.
     */
    static void fromUrlAlphabet(MemorySegment text, int length) {
        for (int i = 0; i < length; i++) {
            int c = text.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            int dash = ((c ^ '-') - 1) >> 31;          // all ones where c == '-'
            int under = ((c ^ '_') - 1) >> 31;         // all ones where c == '_'
            c = (c & ~dash & ~under) | ('+' & dash) | ('/' & under);
            text.set(ValueLayout.JAVA_BYTE, i, (byte) c);
        }
    }

    @Override
    public void close() {
        service.close();
    }

    @Override
    public String toString() {
        return "KmsDecryptSecretProvider[" + service.describe() + "]";
    }

    // ------------------------------------------------------------------- AWS

    private static final class Aws implements Service {

        private final String keyId;
        private final String region;
        private final String body;
        private final AwsJsonCall call;
        private final AwsInstanceRole role;
        private final String accessKeyId;
        private final SecretProvider secretKey;
        private final SecretProvider sessionToken;

        Aws(Map<String, String> settings, String ciphertext) {
            this.keyId = KmsSigningKey.required(settings, "key", "AWS KMS");
            if (!keyId.matches("[A-Za-z0-9:/_.-]+")) {
                throw new IllegalArgumentException("key is a key's ARN, id or alias, not "
                        + keyId);
            }
            this.region = KmsSigningKey.required(settings, "region", "AWS KMS");
            if (!region.matches("[a-z0-9-]+")) {
                throw new IllegalArgumentException("region is a name like eu-central-1, not "
                        + region);
            }
            String[] endpoint = KmsSigningKey.endpoint(settings.get("endpoint"),
                    "kms." + region + ".amazonaws.com");
            this.call = new AwsJsonCall(endpoint[0], Integer.parseInt(endpoint[1]),
                    !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true")),
                    KmsSigningKey.positive(settings, "timeout-millis", 10_000), region, "kms",
                    Clock.systemUTC());
            // The key is named so that AWS refuses a ciphertext of any other key.
            this.body = "{\"CiphertextBlob\":\"" + ciphertext + "\",\"KeyId\":\"" + keyId
                    + "\",\"EncryptionAlgorithm\":\"SYMMETRIC_DEFAULT\"}";
            this.role = AwsInstanceRole.of(settings);
            if (role != null) {
                this.accessKeyId = null;
                this.secretKey = null;
                this.sessionToken = null;
            } else {
                this.accessKeyId = KmsSigningKey.required(settings, "access-key-id", "AWS KMS");
                Map<String, String> key = SecretProviders.nested(settings, "key-");
                if (key.isEmpty()) {
                    throw new IllegalArgumentException("AWS KMS needs credentials: "
                            + "credentials=instance, container or web-identity, or "
                            + "access-key-id with key-provider and its settings");
                }
                this.secretKey = SecretProviders.of(key);
                Map<String, String> session = SecretProviders.nested(settings, "session-token-");
                this.sessionToken = session.isEmpty() ? null : SecretProviders.of(session);
            }
        }

        @Override
        public SecretFetch.Response send(MemorySegment answer) throws IOException {
            if (role == null) {
                return call.send(AWS_TARGET, body, accessKeyId, secretKey, sessionToken, answer);
            }
            try {
                return role.use((id, key, session) -> {
                    try {
                        return call.send(AWS_TARGET, body, id, key, session, answer);
                    } catch (IOException e) {
                        throw new java.io.UncheckedIOException(e);
                    }
                });
            } catch (java.io.UncheckedIOException e) {
                throw e.getCause();
            }
        }

        @Override
        public String[] field() {
            return new String[] {"Plaintext"};
        }

        @Override
        public String hint(int status) {
            return status == 400 || status == 403 ? " - the principal needs kms:Decrypt on "
                    + keyId + ", and the ciphertext has to be one of that key's" : "";
        }

        @Override
        public String reason(MemorySegment answer, int length) {
            return AwsJsonCall.reason(answer, length);
        }

        @Override
        public String describe() {
            return "AWS KMS key " + keyId + " in " + region;
        }

        @Override
        public void close() {
            if (secretKey != null) {
                secretKey.close();
            }
            if (sessionToken != null) {
                sessionToken.close();
            }
        }
    }

    // ------------------------------------------------------------------- GCP

    private static final class Gcp implements Service {

        private static final String NAME =
                "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/:]+";

        private final String key;
        private final String host;
        private final int port;
        private final boolean verify;
        private final int timeoutMillis;
        private final String body;
        private final SecretProvider token;

        Gcp(Map<String, String> settings, String ciphertext) {
            this.key = KmsSigningKey.required(settings, "key", "Google Cloud KMS");
            if (!key.matches(NAME)) {
                throw new IllegalArgumentException("key is a crypto key's resource name, "
                        + "projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k> - Cloud KMS "
                        + "finds the version in the ciphertext - not " + key);
            }
            String[] endpoint = KmsSigningKey.endpoint(settings.get("endpoint"),
                    "cloudkms.googleapis.com");
            this.host = endpoint[0];
            this.port = Integer.parseInt(endpoint[1]);
            this.verify = !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true"));
            this.timeoutMillis = KmsSigningKey.positive(settings, "timeout-millis", 10_000);
            this.body = "{\"ciphertext\":\"" + ciphertext + "\"}";
            this.token = SecretProviders.bearerToken(settings, "Google Cloud KMS");
        }

        @Override
        public SecretFetch.Response send(MemorySegment answer) throws IOException {
            try (Arena arena = Arena.ofConfined();
                 SecretScope bearer = SecretScope.fromProvider(token)) {
                return SecretFetch.send(host, port, verify, timeoutMillis, "POST",
                        "/v1/" + key + ":decrypt", Map.of("Content-Type", "application/json"),
                        List.of(new SecretFetch.SecretHeader("Authorization",
                                AzureKeyVaultKey.bearer(arena, bearer), 7 + bearer.length())),
                        body, answer);
            }
        }

        @Override
        public String[] field() {
            return new String[] {"plaintext"};
        }

        @Override
        public String hint(int status) {
            return status == 403 ? " - the principal needs cloudkms.cryptoKeyVersions"
                    + ".useToDecrypt on " + key : status == 400
                            ? " - a ciphertext of another key, or not one at all" : "";
        }

        @Override
        public String reason(MemorySegment answer, int length) {
            return publicMessage(answer, length, "error", "message");
        }

        @Override
        public String describe() {
            return "Cloud KMS key " + key;
        }

        @Override
        public void close() {
            token.close();
        }
    }

    // ----------------------------------------------------------------- Azure

    private static final class Azure implements Service {

        private static final String API_VERSION = "7.4";

        private final String vaultUri;
        private final String host;
        private final int port;
        private final boolean verify;
        private final int timeoutMillis;
        private final String path;
        private final String body;
        private final SecretProvider token;

        Azure(Map<String, String> settings, String ciphertext) {
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
            String name = SecretNames.require("the key name",
                    KmsSigningKey.required(settings, "key-name", "Azure Key Vault"), false);
            // The version the key was wrapped under: unwrapKey needs it.
            String version = SecretNames.require("the key version",
                    KmsSigningKey.required(settings, "key-version", "Azure Key Vault"), false);
            String algorithm = settings.getOrDefault("algorithm", "RSA-OAEP-256").trim();
            if (!algorithm.matches("RSA-OAEP(-256)?|A(128|192|256)KW")) {
                throw new IllegalArgumentException("algorithm is RSA-OAEP-256, RSA-OAEP or "
                        + "A128KW/A192KW/A256KW (Managed HSM), not " + algorithm);
            }
            this.path = "/keys/" + name + "/" + version + "/unwrapkey?api-version=" + API_VERSION;
            this.body = "{\"alg\":\"" + algorithm + "\",\"value\":\"" + ciphertext + "\"}";
            this.token = SecretProviders.bearerToken(settings, "Azure Key Vault");
        }

        @Override
        public SecretFetch.Response send(MemorySegment answer) throws IOException {
            try (Arena arena = Arena.ofConfined();
                 SecretScope bearer = SecretScope.fromProvider(token)) {
                return SecretFetch.send(host, port, verify, timeoutMillis, "POST", path,
                        Map.of("Content-Type", "application/json"),
                        List.of(new SecretFetch.SecretHeader("Authorization",
                                AzureKeyVaultKey.bearer(arena, bearer), 7 + bearer.length())),
                        body, answer);
            }
        }

        @Override
        public String[] field() {
            return new String[] {"value"};
        }

        @Override
        public String hint(int status) {
            return status == 403 ? " - the identity needs the unwrapKey key permission"
                    : status == 400 ? " - a value wrapped by another key or version, or with "
                            + "another algorithm" : "";
        }

        @Override
        public String reason(MemorySegment answer, int length) {
            return publicMessage(answer, length, "error", "message");
        }

        @Override
        public String describe() {
            return "Key Vault key " + path.substring(6, path.indexOf("/unwrapkey")) + " in "
                    + vaultUri;
        }

        @Override
        public void close() {
            token.close();
        }
    }

    /** A refusal's message, read off-heap and kept to printable ASCII - an error says no secret. */
    private static String publicMessage(MemorySegment answer, int length, String... path) {
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment out = scratch.allocate(300);
            int n;
            try {
                n = JsonOff.string(answer, length, out, path);
            } catch (RuntimeException absent) {
                return "no reason given";
            }
            StringBuilder said = new StringBuilder(); // seclume-allow: an error answer, no secret
            for (int i = 0; i < n; i++) {
                char c = (char) (out.get(ValueLayout.JAVA_BYTE, i) & 0xff);
                said.append(c >= 0x20 && c < 0x7f ? c : '?');
            }
            return said.toString();
        }
    }
}
