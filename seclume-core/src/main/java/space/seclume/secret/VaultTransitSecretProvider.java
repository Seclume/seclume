package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import space.seclume.internal.Base64Off;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A secret stored encrypted by Vault's (or OpenBao's) transit engine,
 * decrypted there on every read: {@code POST transit/decrypt/<key-name>} with
 * the ciphertext, the plaintext written from Vault's answer into the target.
 *
 * <p>The envelope for field encryption's data keys: {@code transit/datakey/wrapped/<key>}
 * makes a key and hands out only its ciphertext ({@code vault:v1:...}); that
 * goes into the configuration, where it is no secret, and the data key exists
 * in clear only in Vault and, once read, in this process's locked memory. A
 * key that leaves Vault never does, so revoking the token or disabling the
 * transit key stops every new start from reading it.
 *
 * <p>Settings: {@code address} (https only), {@code key-name},
 * {@code ciphertext}, optionally {@code transit-mount} ({@code transit}),
 * {@code context} (Base64, for a derived transit key), {@code namespace},
 * {@code verify}, {@code timeout-millis}, {@code max-length}; the token exactly
 * as {@code provider=vault} takes it ({@link SecretProviders#vaultToken}). The
 * token needs {@code update} on {@code transit/decrypt/<key-name>}.
 *
 * <p>Vault answers the plaintext in Base64, inside JSON. Both are read where
 * the answer lies, in native memory ({@link JsonOff}, {@link Base64Off}), and
 * what is written into the target is the decoded secret.
 */
public final class VaultTransitSecretProvider implements SecretProvider {

    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String namespace;
    private final String path;
    private final String body;
    private final SecretProvider token;
    private final int maxLength;

    VaultTransitSecretProvider(Map<String, String> settings, int maxLength) {
        String address = required(settings, "address");
        URI uri = URI.create(address);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("the Vault address must be https://, not "
                    + address + ": the token and the plaintext would travel in the clear");
        }
        this.host = uri.getHost();
        this.port = uri.getPort() > 0 ? uri.getPort() : 443;
        this.verify = !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true"));
        this.timeoutMillis = Integer.parseInt(settings.getOrDefault("timeout-millis", "10000"));
        this.namespace = settings.get("namespace");
        String mount = trimSlashes(settings.getOrDefault("transit-mount", "transit"));
        String keyName = required(settings, "key-name");
        if (!mount.matches("[A-Za-z0-9_./-]+") || !keyName.matches("[A-Za-z0-9_.-]+")) {
            throw new IllegalArgumentException("transit-mount and key-name are path names: "
                    + "letters, digits, '_', '.', '-' (and '/' in a mount)");
        }
        this.path = "/v1/" + mount + "/decrypt/" + keyName;
        String ciphertext = required(settings, "ciphertext");
        if (!ciphertext.matches("vault:v[0-9]+:[A-Za-z0-9+/=]+")) {
            throw new IllegalArgumentException("ciphertext is what transit hands out, "
                    + "vault:v<n>:<Base64> - not " + abbreviate(ciphertext));
        }
        String context = settings.get("context");
        if (context != null && !context.isBlank() && !context.trim().matches("[A-Za-z0-9+/=]+")) {
            throw new IllegalArgumentException("context is Base64, as transit takes it");
        }
        // The ciphertext and the context are no secret: they are what may stand in a
        // configuration because only Vault can open them.
        this.body = "{\"ciphertext\":\"" + ciphertext + "\""
                + (context == null || context.isBlank() ? ""
                        : ",\"context\":\"" + context.trim() + "\"") + "}";
        this.token = SecretProviders.vaultToken(settings);
        this.maxLength = maxLength;
    }

    private static String required(Map<String, String> settings, String name) {
        String value = settings.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("provider=vault-transit needs " + name);
        }
        return value.trim();
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

    private static String abbreviate(String text) {
        return text.length() > 24 ? text.substring(0, 24) + "..." : text;
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
            SecretFetch.Response response = send(answer.segment());
            answer.length(response.bodyLength());
            if (!response.ok()) {
                throw new SecretUnavailableException("Vault answered " + response.status()
                        + " to POST " + path + (response.status() == 403
                                ? " - the token needs update on " + path.substring(4) : "")
                        + (response.status() == 400 ? " - a ciphertext of another key, or a "
                                + "context that does not match" : ""));
            }
            int length;
            try {
                length = JsonOff.string(answer.segment(), answer.length(), encoded.segment(),
                        "data", "plaintext");
            } catch (JsonOff.NotFound e) {
                if (e.getMessage() != null && e.getMessage().contains("longer than the space")) {
                    throw new SecretUnavailableException("the decrypted secret is longer than "
                            + maxLength + " bytes - raise max-length", e);
                }
                throw new SecretUnavailableException("Vault's answer to " + path
                        + " holds no data.plaintext: " + e.getMessage(), e);
            }
            encoded.length(length);
            if (Base64Off.decodedUpperBound(length) > target.byteSize() + 2) {
                throw new SecretUnavailableException("the decrypted secret does not fit into the "
                        + target.byteSize() + " bytes provided - raise max-length");
            }
            try (SecretScope raw = SecretScope.in(arena,
                    Math.max(1, Base64Off.decodedUpperBound(length)))) {
                int decoded = Base64Off.decode(encoded.segment(), 0, length, raw.segment(), 0);
                if (decoded > target.byteSize()) {
                    throw new SecretUnavailableException("the decrypted secret is " + decoded
                            + " bytes and does not fit into the " + target.byteSize()
                            + " bytes provided - raise max-length");
                }
                MemorySegment.copy(raw.segment(), 0, target, 0, decoded);
                return decoded;
            } catch (IllegalArgumentException notBase64) {
                throw new SecretUnavailableException("Vault's plaintext is not Base64",
                        notBase64);
            }
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot reach Vault at " + host + ":" + port
                    + ": " + e.getMessage(), e);
        }
    }

    private SecretFetch.Response send(MemorySegment into) throws IOException {
        try (SecretScope vaultToken = SecretScope.fromProvider(token)) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/json");
            if (namespace != null && !namespace.isBlank()) {
                headers.put("X-Vault-Namespace", namespace);
            }
            return SecretFetch.send(host, port, verify, timeoutMillis, "POST", path, headers,
                    List.of(new SecretFetch.SecretHeader("X-Vault-Token", vaultToken.segment(),
                            vaultToken.length())),
                    body, into);
        }
    }

    @Override
    public void close() {
        token.close();
    }

    @Override
    public String toString() {
        return "VaultTransitSecretProvider[" + host + ":" + port + path + "]";
    }
}
