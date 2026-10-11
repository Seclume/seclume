package space.seclume.tls;

import java.nio.file.Path;
import java.util.List;

import space.seclume.crypto.EcdsaSigner;
import space.seclume.secret.SecretProvider;

/**
 * A client identity whose P-256 private key lives in the provider, not in
 * Java - {@link EcClientIdentity} held to that one curve.
 *
 * <p>Kept for callers that ask for P-256 by name and want anything else
 * refused. How the key gets from its file into CNG or OpenSSL without
 * touching the Java heap is described, and done, in {@link EcClientIdentity};
 * {@link ClientIdentities} builds that class directly and takes P-384 as
 * well.
 */
public final class P256ClientIdentity implements ClientIdentity {

    private final EcClientIdentity identity;

    /**
     * @param certificateChain the client certificate and any intermediates,
     *                         PEM or DER, leaf first
     * @param key              where the private key file comes from - any
     *                         seclume secret provider, so the key can equally
     *                         well arrive from a mount, an agent or encrypted
     */
    public P256ClientIdentity(Path certificateChain, SecretProvider key) {
        this(new EcClientIdentity(certificateChain, key));
    }

    /** The same with the chain already in hand - for tests and for callers that have it. */
    public P256ClientIdentity(List<byte[]> certificateChain, SecretProvider key) {
        this(new EcClientIdentity(certificateChain, key));
    }

    private P256ClientIdentity(EcClientIdentity identity) {
        if (identity.curve() != EcdsaSigner.Curve.P256) {
            identity.close();
            throw new IllegalArgumentException("the client certificate's key is on "
                    + identity.curve() + "; P256ClientIdentity signs with P-256 only - "
                    + "EcClientIdentity takes P-384 as well");
        }
        this.identity = identity;
    }

    @Override
    public List<byte[]> chain() {
        return identity.chain();
    }

    @Override
    public int signatureScheme() {
        return HandshakeSignature.ECDSA_SECP256R1_SHA256;
    }

    @Override
    public byte[] sign(byte[] content) {
        return identity.sign(content);
    }

    @Override
    public void close() {
        identity.close();
    }
}
