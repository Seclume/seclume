package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Map;

import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * An access token from a cloud's instance metadata service, into native memory.
 *
 * <p>The shared half of {@link AzureManagedIdentitySecretProvider} and
 * {@link GcpMetadataSecretProvider}: both ask a link-local HTTP endpoint on the
 * machine they run on, both are answered with JSON whose {@code access_token}
 * is the credential, and in both the token must go from the socket to the
 * target segment without becoming a {@code String}.
 */
final class MetadataToken {

    private MetadataToken() {
    }

    /**
     * Fetches and writes {@code access_token} into {@code target}.
     *
     * @param who a name for messages - "Azure IMDS", "the GCP metadata server"
     * @return how many bytes of token were written
     */
    static int fetch(String who, String host, int port, int timeoutMillis, String path,
            Map<String, String> headers, MemorySegment target) {
        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
            SecretFetch.Response response;
            try {
                response = SecretFetch.sendLinkLocal(host, port, timeoutMillis, "GET", path,
                        headers, answer.segment());
            } catch (IOException unreachable) {
                throw new SecretUnavailableException(who + " could not be reached at " + host
                        + ":" + port + " - " + unreachable.getMessage() + ". This provider "
                        + "only works on a machine of that cloud with an identity assigned",
                        unreachable);
            }
            answer.length(response.bodyLength());
            if (!response.ok()) {
                // The body is not quoted: an error document from a token
                // endpoint is not a place to go looking for what is in it.
                throw new SecretUnavailableException(who + " answered " + response.status()
                        + ". 400 usually means no identity is assigned to this machine or the "
                        + "resource or scope asked for is wrong; 404 that the identity named "
                        + "does not exist");
            }
            if (!JsonOff.has(answer.segment(), response.bodyLength(), "access_token")) {
                throw new SecretUnavailableException(who + " answered without an access_token");
            }
            // Into a scratch segment the size of the whole answer first, so
            // that a token too long for the target is told apart from a
            // document that has none - JsonOff reports both the same way.
            try (SecretScope token = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
                int length = JsonOff.string(answer.segment(), response.bodyLength(),
                        token.segment(), "access_token");
                token.length(length);
                if (length == 0) {
                    throw new SecretUnavailableException(who + " answered with an empty token");
                }
                if (length > target.byteSize()) {
                    throw new SecretUnavailableException("the token from " + who + " is "
                            + "longer than the " + target.byteSize() + " bytes allowed for it - "
                            + "raise max-length");
                }
                MemorySegment.copy(token.segment(), 0, target, 0, length);
                return length;
            }
        } catch (JsonOff.NotFound malformed) {
            throw new SecretUnavailableException(who + " answered with something that is not "
                    + "the token document it should be: " + malformed.getMessage(), malformed);
        }
    }
}
