package space.seclume.gcp;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.auth.oauth2.ServiceAccountCredentials;

import space.seclume.internal.JsonOff;
import space.seclume.keys.SeclumeKeys;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;

/**
 * Google Cloud service account credentials whose private key stays in
 * OpenSSL.
 *
 * <pre>
 * GoogleCredentials credentials = SeclumeGcp.credentials(
 *         "provider=file&amp;path=/run/secrets/service-account.json&amp;scopes=https://www.googleapis.com/auth/cloud-platform");
 *
 * Storage storage = StorageOptions.newBuilder().setCredentials(credentials).build().getService();
 * </pre>
 *
 * <p>{@code GoogleCredentials.fromStream} reads the key file into a
 * {@code String}, parses it with a JSON library into more of them, and makes
 * the key an {@code RSAPrivateCrtKey} - the service account on the heap for
 * the life of the application. Here the file is read by a secret provider
 * into native memory, its {@code private_key} unescaped there and decoded by
 * OpenSSL; the credentials hold an {@code OpenSslPrivateKey}, and the JWTs the
 * library signs to get its access tokens are signed through seclume's JCA
 * provider. The public fields - the account's e-mail, the key's id, the
 * project - are ordinary strings.
 *
 * <p>What the library gets back is an access token, valid for an hour, that it
 * holds as a {@code String}: the protection here is for the key, which is valid
 * until someone deletes it.
 */
public final class SeclumeGcp {

    private SeclumeGcp() {
    }

    /**
     * The service account in the JSON key file named by {@code spec} - the
     * secret provider's options, plus {@code scopes=} (space- or
     * comma-separated) when the client library does not set them.
     */
    public static ServiceAccountCredentials credentials(String spec) {
        Map<String, String> options = new LinkedHashMap<>();
        for (String pair : (spec.startsWith("?") ? spec.substring(1) : spec).split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                options.put(URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
        String scopes = options.remove("scopes");
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no key file named: add provider= and its "
                    + "options, e.g. provider=file&path=/run/secrets/service-account.json");
        }
        if (!options.containsKey("max-length") && !options.containsKey("maxLength")) {
            options.put("max-length", "32768");        // a key file is about 2.4 KB
        }
        try (SecretProvider file = SecretProviders.of(options);
             SecretScope json = SecretScope.fromProvider(file);
             SecretScope key = SecretScope.allocate(json.length());
             Arena arena = Arena.ofConfined()) {
            MemorySegment text = arena.allocate(1024);
            String type = field(json, text, "type");
            if (!"service_account".equals(type)) {
                throw new IllegalArgumentException("the key file is a '" + type + "', not a "
                        + "service account's");
            }
            key.length(JsonOff.string(json.segment(), json.length(), key.segment(),
                    "private_key"));
            PrivateKey privateKey = SeclumeKeys.privateKey(new SecretProvider() {
                @Override
                public int writeSecret(MemorySegment target) {
                    MemorySegment.copy(key.segment(), 0, target, 0, key.length());
                    return key.length();
                }

                @Override
                public int maxSecretLength() {
                    return key.length();
                }
            });
            ServiceAccountCredentials.Builder builder = ServiceAccountCredentials.newBuilder()
                    .setClientEmail(field(json, text, "client_email"))
                    .setPrivateKey(privateKey)
                    .setPrivateKeyId(optional(json, text, "private_key_id"))
                    .setClientId(optional(json, text, "client_id"))
                    .setProjectId(optional(json, text, "project_id"));
            String tokenUri = optional(json, text, "token_uri");
            if (tokenUri != null) {
                builder.setTokenServerUri(URI.create(tokenUri));
            }
            if (scopes != null) {
                builder.setScopes(Arrays.stream(scopes.split("[ ,]+")).filter(s -> !s.isBlank())
                        .toList());
            } else {
                builder.setScopes(List.of());
            }
            return builder.build();
        }
    }

    /** A public field of the key file - an e-mail address, an id. */
    private static String field(SecretScope json, MemorySegment text, String name) {
        try {
            return ascii(text, JsonOff.string(json.segment(), json.length(), text, name));
        } catch (JsonOff.NotFound e) {
            throw new SecretUnavailableException("the key file has no " + name, e);
        }
    }

    private static String optional(SecretScope json, MemorySegment text, String name) {
        return JsonOff.has(json.segment(), json.length(), name) ? field(json, text, name) : null;
    }

    private static String ascii(MemorySegment bytes, int length) {
        return new String(bytes.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE), // seclume-allow: a public field of the key file
                StandardCharsets.UTF_8);
    }
}
