package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64; // seclume-allow: public keys, hashes and signatures
import java.util.Map;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A key in AWS KMS ({@code KeyUsage SIGN_VERIFY}), signing there:
 * {@code GetPublicKey} for its public half, {@code Sign} with
 * {@code MessageType DIGEST} - the hash made here - for each signature, both
 * signed with SigV4 ({@link AwsJsonCall}).
 *
 * <p>Settings: {@code key} (its id, ARN or {@code alias/...}), {@code region},
 * and the credentials as {@code provider=aws-secrets-manager} takes them -
 * {@code credentials=instance|container|web-identity}, or
 * {@code access-key-id} with {@code key-provider} and optionally
 * {@code session-token-provider}; optionally {@code endpoint} (a VPC endpoint,
 * {@code host[:port]}), {@code verify}, {@code timeout-millis}. The principal
 * needs {@code kms:GetPublicKey} and {@code kms:Sign} on the key.
 */
final class AwsKmsKey implements KmsSigningKey.Service {

    private static final String SERVICE = "kms";

    private final String keyId;
    private final String region;
    private final AwsJsonCall call;
    private final AwsInstanceRole role;
    private final String accessKeyId;
    private final SecretProvider secretKey;
    private final SecretProvider sessionToken;
    private volatile String keySpec = "";

    AwsKmsKey(Map<String, String> settings) {
        // "key", not "key-id": key- is where the secret access key's provider is set.
        this.keyId = KmsSigningKey.required(settings, "key", "AWS KMS");
        this.region = KmsSigningKey.required(settings, "region", "AWS KMS");
        if (!region.matches("[a-z0-9-]+")) {
            throw new IllegalArgumentException("region is a name like eu-central-1, not "
                    + region);
        }
        String[] endpoint = KmsSigningKey.endpoint(settings.get("endpoint"),
                SERVICE + "." + region + ".amazonaws.com");
        this.call = new AwsJsonCall(endpoint[0], Integer.parseInt(endpoint[1]),
                !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true")),
                KmsSigningKey.positive(settings, "timeout-millis", 10_000), region, SERVICE,
                Clock.systemUTC());
        this.role = AwsInstanceRole.of(settings);
        if (role != null) {
            this.accessKeyId = null;
            this.secretKey = null;
            this.sessionToken = null;
        } else {
            this.accessKeyId = KmsSigningKey.required(settings, "access-key-id", "AWS KMS");
            Map<String, String> key = SecretProviders.nested(settings, "key-");
            if (key.isEmpty()) {
                throw new IllegalArgumentException("a key in AWS KMS needs credentials: "
                        + "credentials=instance, container or web-identity, or access-key-id "
                        + "with key-provider and its settings");
            }
            this.secretKey = SecretProviders.of(key);
            Map<String, String> session = SecretProviders.nested(settings, "session-token-");
            this.sessionToken = session.isEmpty() ? null : SecretProviders.of(session);
        }
    }

    @Override
    public String describe() {
        return "AWS KMS key " + keyId + " in " + region;
    }

    @Override
    public byte[] publicKey() throws IOException {
        String answer = call("TrentService.GetPublicKey", "{\"KeyId\":\"" + json(keyId) + "\"}");
        String usage = field(answer, "KeyUsage");
        if (!usage.equals("SIGN_VERIFY")) {
            throw new IOException("the key's KeyUsage is " + usage + ", not SIGN_VERIFY - "
                    + "it does not sign");
        }
        keySpec = field(answer, "KeySpec");
        if (!keySpec.startsWith("ECC_NIST_") && !keySpec.startsWith("RSA_")) {
            throw new IOException("the key is " + keySpec + " - ECC_NIST_P256, ECC_NIST_P384 "
                    + "and RSA keys sign for TLS");
        }
        return Base64.getDecoder().decode(field(answer, "PublicKey")); // seclume-allow: a public key
    }

    @Override
    public byte[] sign(HashAlgorithm digest, boolean pss, byte[] hash) throws IOException {
        String bits = switch (digest) {
            case SHA_256 -> "256";
            case SHA_384 -> "384";
            case SHA_512 -> "512";
            default -> throw new IllegalArgumentException("AWS KMS signs SHA-2 hashes, not "
                    + digest);
        };
        String algorithm = keySpec.startsWith("RSA_")
                ? (pss ? "RSASSA_PSS_SHA_" : "RSASSA_PKCS1_V1_5_SHA_") + bits
                : "ECDSA_SHA_" + bits;
        String answer = call("TrentService.Sign", "{\"KeyId\":\"" + json(keyId)
                + "\",\"Message\":\"" + Base64.getEncoder().encodeToString(hash) // seclume-allow: a public hash
                + "\",\"MessageType\":\"DIGEST\",\"SigningAlgorithm\":\"" + algorithm + "\"}");
        return Base64.getDecoder().decode(field(answer, "Signature")); // seclume-allow: a public signature
    }

    /** One operation; its answer - a public key, a signature - as text. */
    private String call(String target, String body) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment answer = arena.allocate(SecretFetch.MAX_RESPONSE);
            SecretFetch.Response response;
            if (role != null) {
                try {
                    response = role.use((id, key, session) -> {
                        try {
                            return call.send(target, body, id, key, session, answer);
                        } catch (IOException e) {
                            throw new java.io.UncheckedIOException(e);
                        }
                    });
                } catch (java.io.UncheckedIOException e) {
                    throw e.getCause();
                }
            } else {
                response = call.send(target, body, accessKeyId, secretKey, sessionToken, answer);
            }
            if (!response.ok()) {
                String reason = AwsJsonCall.reason(answer, response.bodyLength());
                throw new IOException("AWS KMS answered " + response.status() + " to "
                        + target.substring(target.indexOf('.') + 1) + " for " + keyId + ": "
                        + reason + (reason.contains("AccessDenied") ? " - the principal needs "
                                + "kms:GetPublicKey and kms:Sign on the key" : ""));
            }
            // seclume-allow: AWS KMS's answer about a key - a public key or a signature
            return new String(answer.asSlice(0, response.bodyLength())
                    .toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
        }
    }

    private static String field(String answer, String name) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            // seclume-allow: AWS KMS's answer about a key, which holds no secret
            byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
            MemorySegment json = arena.allocate(Math.max(1, bytes.length));
            MemorySegment.copy(bytes, 0, json, ValueLayout.JAVA_BYTE, 0, bytes.length);
            MemorySegment out = arena.allocate(Math.max(16, bytes.length));
            int written = JsonOff.string(json, bytes.length, out, name);
            // seclume-allow: a public key, a signature or a key's type
            return new String(out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);
        } catch (JsonOff.NotFound e) {
            throw new IOException("AWS KMS's answer holds no " + name, e);
        }
    }

    private static String json(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public void close() {
        try {
            if (secretKey != null) {
                secretKey.close();
            }
        } finally {
            try {
                if (sessionToken != null) {
                    sessionToken.close();
                }
            } finally {
                if (role != null && role != AwsInstanceRole.shared()) {
                    role.close();
                }
            }
        }
    }
}
