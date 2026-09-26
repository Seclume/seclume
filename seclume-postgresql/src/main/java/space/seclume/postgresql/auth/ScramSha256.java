package space.seclume.postgresql.auth;

import java.lang.foreign.MemorySegment;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.Scram;

/**
 * SCRAM-SHA-256 as PostgreSQL speaks it - the client in {@link Scram}, which
 * lived here until Kafka needed it too.
 */
public final class ScramSha256 extends Scram {

    public ScramSha256() {
        super(HashAlgorithm.SHA_256);
    }

    /** @param nonceBytes the raw bytes of the client nonce before base64 encoding */
    public ScramSha256(int nonceBytes) {
        super(HashAlgorithm.SHA_256, nonceBytes);
    }

    /** Only for tests with fixed vectors: the nonce is supplied. */
    ScramSha256(MemorySegment fixedNonce, int length) {
        super(HashAlgorithm.SHA_256, fixedNonce, length);
    }
}
