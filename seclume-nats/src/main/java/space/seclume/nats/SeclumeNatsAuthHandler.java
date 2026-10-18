package space.seclume.nats;

import io.nats.client.AuthHandler;
import space.seclume.jfr.Observed;
import space.seclume.jfr.SeclumeEvents;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * An {@link AuthHandler} that signs the server's challenge in native memory.
 *
 * <p>The official client's {@code Nats.credentials(...)} and {@code NKey} read
 * the seed into a {@code byte[]} and a {@code char[]}, decode it on the heap,
 * and hand the key to BouncyCastle or JCA. Here the secret provider is read
 * into a {@link SecretScope} at each connect or reconnect, the Base32 seed is
 * decoded in a confined off-heap arena, and {@link space.seclume.crypto.Ed25519}
 * computes the public key and the 64-byte signature in native memory. Only the
 * public key ({@code U...}), the optional user JWT, and the signature are
 * returned to the client.
 */
final class SeclumeNatsAuthHandler implements AuthHandler {

    private final SecretProvider seedOrCreds;
    private final SecretProvider separateJwt;
    private final String target;

    SeclumeNatsAuthHandler(SecretProvider seedOrCreds, SecretProvider separateJwt, String target) {
        this.seedOrCreds = seedOrCreds;
        this.separateJwt = separateJwt;
        this.target = target == null ? "" : target;
    }

    @Override
    public byte[] sign(byte[] nonce) {
        Observed.secretUse("nats", target, separateJwt != null ? "jwt" : "nkey");
        SeclumeEvents.Signature sigEvent = Observed.beginSignature();
        boolean succeeded = false;
        try (SecretScope scope = SecretScope.fromProvider(seedOrCreds)) {
            byte[] signature = NKeyOff.sign(scope.segment(), scope.length(), nonce);
            succeeded = true;
            return signature;
        } finally {
            Observed.endSignature(sigEvent, "Ed25519", "sign", succeeded);
        }
    }

    @Override
    public char[] getID() { // seclume-allow: AuthHandler.getID returns the public NKey (U...)
        try (SecretScope scope = SecretScope.fromProvider(seedOrCreds)) {
            return NKeyOff.publicKey(scope.segment(), scope.length());
        }
    }

    @Override
    public char[] getJWT() { // seclume-allow: AuthHandler.getJWT returns the public user JWT
        if (separateJwt != null) {
            try (SecretScope scope = SecretScope.fromProvider(separateJwt)) {
                return NKeyOff.extractStandaloneJwt(scope.segment(), scope.length());
            }
        }
        try (SecretScope scope = SecretScope.fromProvider(seedOrCreds)) {
            return NKeyOff.extractJwt(scope.segment(), scope.length());
        }
    }
}
