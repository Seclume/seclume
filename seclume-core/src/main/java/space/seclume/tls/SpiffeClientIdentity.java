package space.seclume.tls;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;

import space.seclume.secret.SpiffeWorkloadApi;
import space.seclume.secret.VaultPkiIssuer;

/**
 * A database connection's client certificate is the workload's X.509-SVID,
 * from the SPIFFE Workload API - a SPIRE agent - with its key read off the
 * socket into native memory and handed to OpenSSL or CNG
 * ({@link SpiffeWorkloadApi}), never a {@code PrivateKey}.
 *
 * <p>{@code clientCertSpiffe=unix:///run/spire/agent.sock} (or {@code true}
 * for the socket {@code SPIFFE_ENDPOINT_SOCKET} names) configures it. SPIRE
 * rotates an SVID when half its life is gone; this asks again once 55% has
 * passed, and again a little later each time the agent still has the same
 * one. The new SVID is presented from the next handshake on; one under way
 * keeps its own ({@link RenewingClientIdentity}). The database decides by
 * the certificate - a URI SAN {@code spiffe://...}, a common name - which
 * user it logs in as.
 */
final class SpiffeClientIdentity extends RenewingClientIdentity {

    /** When to ask the agent for the next SVID: a little after it rotates, at half. */
    static final double ASK_AT = 0.55;

    private final SpiffeWorkloadApi api;
    private volatile String spiffeId = "an SVID";

    SpiffeClientIdentity(SpiffeWorkloadApi api, Clock clock) {
        super(clock);
        this.api = api;
        try {
            start("seclume-spiffe " + api.socket());
        } catch (IOException | RuntimeException e) {
            close();
            // An argument of the connection, as the drivers read it: they turn
            // it into the SQLException (08001) a connect that cannot work is.
            throw new IllegalArgumentException("no X.509-SVID from the Workload API at "
                    + api.socket() + ": " + e.getMessage(), e);
        }
    }

    @Override
    Generation obtain(Generation current) throws IOException {
        SpiffeWorkloadApi.X509Svid svid = api.fetchX509Svid();
        spiffeId = svid.spiffeId();
        if (current != null && svid.chain().get(0).getSerialNumber().equals(current.serial)) {
            svid.key().close();                   // the same one: not rotated yet
            return null;
        }
        return new Generation(svid.chain(), svid.key());
    }

    @Override
    Instant nextLook(Generation generation) {
        return VaultPkiIssuer.renewalTime(generation.notBefore, generation.notAfter, ASK_AT);
    }

    @Override
    String name() {
        return spiffeId;
    }

    @Override
    String source() {
        return api.socket().toString();
    }

    @Override
    void release() {
        // the agent keeps nothing of ours
    }
}
