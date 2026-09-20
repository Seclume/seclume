package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.List;
import java.util.Map;

import space.seclume.internal.Base64Off;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A secret from Google Secret Manager, read without it becoming a
 * {@code String}.
 *
 * <p>The Google client library answers with
 * {@code response.getPayload().getData().toStringUtf8()}. Before that there is
 * a protobuf {@code ByteString}, before that a decoded {@code byte[]}, before
 * that the Base64 in the JSON - four heap copies of the password for one read.
 *
 * <p>Here the JSON lands in native memory, {@link JsonOff} takes the Base64
 * field out of it, and {@link Base64Off} decodes segment to segment straight
 * into the caller's target. The password is never anything but bytes in native
 * memory.
 *
 * <h2>The token</h2>
 *
 * <p>A bearer token, from another {@link SecretProvider} and written into the
 * header out of native memory - the same arrangement as
 * {@link AzureKeyVaultSecretProvider}, and for the same reason: Google does
 * not sign the request, so nothing forces the token into a string.
 *
 * <p>Obtaining the token is not this class's job. On GKE the metadata server
 * hands one out, and a sidecar or an init container writing it to a file is
 * the arrangement that works everywhere; either way it is a provider.
 */
public final class GcpSecretManagerSecretProvider implements SecretProvider {

    private static final String HOST = "secretmanager.googleapis.com";

    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String resource;
    private final SecretProvider token;
    private final int maxLength;

    /**
     * @param project the project id
     * @param name    the secret's name
     * @param version a version number, or {@code null} for {@code latest}
     * @param token   where the bearer token comes from
     */
    public GcpSecretManagerSecretProvider(String project, String name, String version,
            SecretProvider token, int maxLength) {
        this(project, name, version, token, HOST, 443, true, 10_000, maxLength);
    }

    /** The same with the endpoint under the caller's control - for tests. */
    public GcpSecretManagerSecretProvider(String project, String name, String version,
            SecretProvider token, String host, int port, boolean verify, int timeoutMillis,
            int maxLength) {
        this.host = host;
        this.port = port;
        this.verify = verify;
        this.timeoutMillis = timeoutMillis;
        this.resource = "projects/" + project + "/secrets/" + name + "/versions/"
                + (version == null || version.isEmpty() ? "latest" : version);
        this.token = token;
        this.maxLength = maxLength;
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE);
             SecretScope bearer = SecretScope.fromProvider(token)) {

            SecretFetch.Response response = SecretFetch.send(host, port, verify, timeoutMillis,
                    "GET", "/v1/" + resource + ":access", Map.of(),
                    List.of(new SecretFetch.SecretHeader("Authorization",
                            prefixed(arena, bearer), 7 + bearer.length())),
                    null, answer.segment());
            if (!response.ok()) {
                throw new SecretUnavailableException("Google Secret Manager answered "
                        + response.status() + " for " + resource + ". 403 means the token may "
                        + "not access this version, 404 that it does not exist");
            }
            answer.length(response.bodyLength());

            // The payload is Base64 inside the JSON, so there are two steps
            // and both stay in native memory: out of the document into a
            // scope, and out of that into the caller's target.
            try (SecretScope encoded = SecretScope.in(arena, maxLength * 2)) {
                int length = JsonOff.string(answer.segment(), answer.length(),
                        encoded.segment(), "payload", "data");
                encoded.length(length);
                try {
                    return Base64Off.decode(encoded.segment(), 0, length, target, 0);
                } catch (RuntimeException notBase64) {
                    throw new SecretUnavailableException(
                            "the payload from Google Secret Manager is not valid Base64",
                            notBase64);
                }
            }
        } catch (IOException e) {
            throw new SecretUnavailableException(
                    "cannot reach Google Secret Manager at " + host + ": " + e.getMessage(), e);
        } catch (JsonOff.NotFound e) {
            throw new SecretUnavailableException(
                    "Google Secret Manager answered, but not in a shape this understands: "
                    + e.getMessage(), e);
        }
    }

    /** {@code Bearer } and the token, joined in native memory. */
    private static MemorySegment prefixed(Arena arena, SecretScope bearer) {
        MemorySegment value = arena.allocate(7L + bearer.length());
        byte[] word = {'B', 'e', 'a', 'r', 'e', 'r', ' '}; // seclume-allow: a constant word, not a secret
        MemorySegment.copy(word, 0, value, ValueLayout.JAVA_BYTE, 0, 7);
        MemorySegment.copy(bearer.segment(), 0, value, 7, bearer.length());
        return value;
    }

    @Override
    public void close() {
        token.close();
    }
}
