package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.time.Instant;
import java.util.List;

/**
 * A JWT-SVID from the SPIFFE Workload API as a secret - a bearer token for an
 * audience ({@code provider=spiffe-jwt&audience=https://api.example.com}),
 * written from the agent's socket through native memory into wherever the
 * token is sent: an {@code Authorization} header, Kafka's OAUTHBEARER,
 * PostgreSQL 18's {@code oauth} login. Every SPIFFE library hands the token
 * out as a {@code String}; here it never is one.
 *
 * <p>Each read asks the agent - a local socket, and an agent that caches - so
 * the token is the one valid now. Its {@code exp}, read where it lies, is
 * when a pool replaces the connections it opened ({@link ExpiringCredentials}).
 *
 * <p>Settings: {@code audience} (comma separated), optionally {@code socket}
 * (else {@code SPIFFE_ENDPOINT_SOCKET}), {@code spiffe-id} (which of the
 * workload's identities), {@code timeout-millis}.
 */
public final class SpiffeJwtSecretProvider implements SecretProvider, ExpiringCredentials {

    private final SpiffeWorkloadApi api;
    private final List<String> audiences;
    private final String spiffeId;
    private final int maxLength;
    private volatile Instant expiresAt;

    public SpiffeJwtSecretProvider(SpiffeWorkloadApi api, List<String> audiences,
            String spiffeId, int maxLength) {
        if (audiences.isEmpty()) {
            throw new IllegalArgumentException("a JWT-SVID needs an audience: audience=...");
        }
        this.api = api;
        this.audiences = List.copyOf(audiences);
        this.spiffeId = spiffeId;
        this.maxLength = maxLength;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        try {
            SpiffeWorkloadApi.JwtSvid svid = api.fetchJwtSvid(audiences, spiffeId, target);
            expiresAt = svid.expiresAt();
            return svid.length();
        } catch (IOException e) {
            throw new SecretUnavailableException("no JWT-SVID for " + audiences + " from the "
                    + "Workload API at " + api.socket() + ": " + e.getMessage(), e);
        }
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public Instant credentialsValidUntil() {
        return expiresAt;
    }
}
