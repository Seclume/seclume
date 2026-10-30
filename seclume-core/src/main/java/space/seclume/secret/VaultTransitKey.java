package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64; // seclume-allow: public keys, hashes and signatures
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A key in Vault's (or OpenBao's) transit engine, signing there:
 * {@code transit/keys/<name>} for its public half, {@code transit/sign/<name>}
 * with the hash made here ({@code prehashed}) for each signature.
 *
 * <p>Settings: {@code address} (https only), {@code key-name}, and optionally
 * {@code transit-mount} ({@code transit}), {@code key-version} (the latest when
 * it is opened - and then that one, so that a key rotated in Vault does not
 * part from the certificate issued for it), {@code namespace}, {@code verify},
 * {@code timeout-millis}; the Vault token exactly as {@code provider=vault}
 * takes it ({@link SecretProviders#vaultToken}). The token needs
 * {@code read} on {@code transit/keys/<name>} and {@code update} on
 * {@code transit/sign/<name>/*}.
 */
final class VaultTransitKey implements KmsSigningKey.Service {

    private static final Pattern ERRORS = Pattern.compile("\"errors\"\\s*:\\s*\\[(.*?)\\]",
            Pattern.DOTALL);

    private final String address;
    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String namespace;
    private final String mount;
    private final String keyName;
    private final SecretProvider token;
    private long version;

    VaultTransitKey(Map<String, String> settings) {
        this.address = required(settings, "address");
        URI uri = URI.create(address);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("the Vault address must be https://, not "
                    + address + ": the token would travel in the clear");
        }
        this.host = uri.getHost();
        this.port = uri.getPort() > 0 ? uri.getPort() : 443;
        this.verify = !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true"));
        this.timeoutMillis = positive(settings, "timeout-millis", 10_000);
        this.namespace = settings.get("namespace");
        this.mount = trimSlashes(settings.getOrDefault("transit-mount", "transit"));
        this.keyName = required(settings, "key-name");
        if (!mount.matches("[A-Za-z0-9_./-]+") || !keyName.matches("[A-Za-z0-9_.-]+")) {
            throw new IllegalArgumentException("transit-mount and key-name are path names: "
                    + "letters, digits, '_', '.', '-' (and '/' in a mount)");
        }
        String pinned = settings.get("key-version");
        this.version = pinned == null || pinned.isBlank() ? 0 : positive(settings,
                "key-version", 0);
        this.token = SecretProviders.vaultToken(settings);
    }

    private static String required(Map<String, String> settings, String name) {
        String value = settings.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("a key in Vault's transit engine needs " + name);
        }
        return value.trim();
    }

    private static int positive(Map<String, String> settings, String name, int fallback) {
        String value = settings.get(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed > 0) {
                return parsed;
            }
        } catch (NumberFormatException e) {
            // said below
        }
        throw new IllegalArgumentException(name + " is a positive whole number, not " + value);
    }

    private static String trimSlashes(String path) {
        String trimmed = path.trim();
        while (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    @Override
    public synchronized String describe() {
        return "Vault transit key " + keyName + (version > 0 ? " v" + version : "") + " at "
                + address + "/v1/" + mount;
    }

    @Override
    public byte[] publicKey() throws IOException {
        String path = "/v1/" + mount + "/keys/" + keyName;
        String answer = call("GET", path, null);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment json = text(arena, answer);
            int length = (int) json.byteSize();
            String type = string(arena, json, length, "data", "type");
            if (!type.startsWith("ecdsa-p256") && !type.startsWith("ecdsa-p384")
                    && !type.startsWith("rsa-")) {
                throw new IOException("the transit key " + keyName + " is of type " + type
                        + "; ecdsa-p256, ecdsa-p384 and rsa-2048/3072/4096 sign for TLS");
            }
            long latest = JsonOff.number(json, length, "data", "latest_version");
            synchronized (this) {
                if (version == 0) {
                    version = latest;
                } else if (version > latest) {
                    throw new IOException("key-version " + version + " is past the latest, "
                            + latest);
                }
            }
            String pem = string(arena, json, length, "data", "keys", Long.toString(version()),
                    "public_key");
            return der(pem);
        } catch (JsonOff.NotFound e) {
            throw new IOException("Vault's answer to " + path + " holds no public key for "
                    + "version " + version() + " - is it a key that signs?", e);
        }
    }

    private synchronized long version() {
        return version;
    }

    @Override
    public byte[] sign(HashAlgorithm digest, boolean pss, byte[] hash) throws IOException {
        String algorithm = switch (digest) {
            case SHA_256 -> "sha2-256";
            case SHA_384 -> "sha2-384";
            case SHA_512 -> "sha2-512";
            default -> throw new IllegalArgumentException("transit signs SHA-2 hashes, not "
                    + digest);
        };
        String path = "/v1/" + mount + "/sign/" + keyName + "/" + algorithm;
        StringBuilder body = new StringBuilder("{\"input\":\"")
                .append(Base64.getEncoder().encodeToString(hash)) // seclume-allow: a public hash
                .append("\",\"prehashed\":true,\"key_version\":").append(version())
                .append(",\"marshaling_algorithm\":\"asn1\"");
        if (pss) {
            body.append(",\"signature_algorithm\":\"pss\",\"salt_length\":\"hash\"");
        } else {
            body.append(",\"signature_algorithm\":\"pkcs1v15\"");
        }
        String answer = call("POST", path, body.append('}').toString());
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment json = text(arena, answer);
            String signature = string(arena, json, (int) json.byteSize(), "data", "signature");
            // vault:v<version>:<base64>
            int colon = signature.lastIndexOf(':');
            if (!signature.startsWith("vault:") || colon < 0) {
                throw new IOException("Vault's signature is not vault:v<n>:<base64>");
            }
            return Base64.getDecoder().decode(signature.substring(colon + 1)); // seclume-allow: a public signature
        } catch (JsonOff.NotFound e) {
            throw new IOException("Vault's answer to " + path + " holds no signature", e);
        }
    }

    /** One request with the token; the answer - public: a key, a signature - as text. */
    private String call(String method, String path, String body) throws IOException {
        try (Arena arena = Arena.ofConfined();
             SecretScope vaultToken = SecretScope.fromProvider(token)) {
            MemorySegment answer = arena.allocate(SecretFetch.MAX_RESPONSE);
            Map<String, String> headers = new LinkedHashMap<>();
            if (body != null) {
                headers.put("Content-Type", "application/json");
            }
            if (namespace != null && !namespace.isBlank()) {
                headers.put("X-Vault-Namespace", namespace);
            }
            SecretFetch.Response response = SecretFetch.send(host, port, verify, timeoutMillis,
                    method, path, headers,
                    List.of(new SecretFetch.SecretHeader("X-Vault-Token", vaultToken.segment(),
                            vaultToken.length())),
                    body, answer);
            // seclume-allow: Vault's answer about a key - a public key, a signature or an error
            String text = new String(answer.asSlice(0, response.bodyLength())
                    .toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
            if (!response.ok()) {
                Matcher errors = ERRORS.matcher(text);
                String reason = errors.find() ? errors.group(1).trim() : "no reason given";
                throw new IOException("Vault answered " + response.status() + " to " + method
                        + " " + path + ": " + (reason.length() > 300
                                ? reason.substring(0, 300) + "..." : reason)
                        + (response.status() == 403 ? " - the token needs read on "
                                + "transit/keys/" + keyName + " and update on transit/sign/"
                                + keyName + "/*" : ""));
            }
            return text;
        }
    }

    private static MemorySegment text(Arena arena, String text) {
        // seclume-allow: Vault's answer about a key, which holds no secret
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        MemorySegment json = arena.allocate(Math.max(1, bytes.length));
        MemorySegment.copy(bytes, 0, json, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return json.asSlice(0, bytes.length);
    }

    private static String string(Arena arena, MemorySegment json, int length, String... path) {
        MemorySegment out = arena.allocate(Math.max(16, length));
        int written = JsonOff.string(json, length, out, path);
        // seclume-allow: a public key, a type or a signature
        return new String(out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE),
                StandardCharsets.UTF_8);
    }

    /** The DER inside a {@code PUBLIC KEY} PEM. */
    static byte[] der(String pem) throws IOException {
        int begin = pem.indexOf("-----BEGIN PUBLIC KEY-----");
        int end = pem.indexOf("-----END PUBLIC KEY-----");
        if (begin < 0 || end < begin) {
            throw new IOException("the public key is not a PUBLIC KEY PEM");
        }
        String body = pem.substring(begin + "-----BEGIN PUBLIC KEY-----".length(), end)
                .replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(body); // seclume-allow: a public key
        } catch (IllegalArgumentException e) {
            throw new IOException("the public key PEM is not Base64", e);
        }
    }

    @Override
    public void close() {
        token.close();
    }
}
