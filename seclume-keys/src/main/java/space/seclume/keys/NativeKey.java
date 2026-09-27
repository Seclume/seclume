package space.seclume.keys;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import space.seclume.crypto.OpenSshPrivateKey;
import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The key in OpenSSL's memory, and the lock that keeps {@link #destroy()} from
 * freeing it under a signature in progress.
 *
 * <p>Signatures run concurrently - a server makes one per handshake, and
 * OpenSSL 3 signs with a shared {@code EVP_PKEY} from any number of threads -
 * so they share the read side of the lock; only freeing takes the write side.
 */
final class NativeKey {

    /** {@code RSA}, {@code EC} or {@code Ed25519}: what the key is, in JCA's words. */
    final String type;
    final PublicKey publicKey;
    private final OpenSslSigningKey key;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private boolean destroyed;                    // guarded by lock

    private NativeKey(String type, PublicKey publicKey, OpenSslSigningKey key) {
        this.type = type;
        this.publicKey = publicKey;
        this.key = key;
    }

    /** Reads the key once from {@code secret}, PEM or DER, and decodes it in OpenSSL. */
    static NativeKey read(SecretProvider secret) {
        if (!OpenSslSigningKey.available()) {
            throw new IllegalStateException("a private key off the heap needs OpenSSL 3 on "
                    + "64-bit Linux, which is not there");
        }
        OpenSslSigningKey decoded;
        try (SecretScope encoded = SecretScope.fromProvider(secret)) {
            if (OpenSshPrivateKey.is(encoded.segment(), encoded.length())) {
                try (SecretScope der = SecretScope.allocate(
                        OpenSshPrivateKey.maxDerLength(encoded.length()))) {
                    der.length(OpenSshPrivateKey.toDer(encoded.segment(), encoded.length(),
                            der.segment()));
                    decoded = OpenSslSigningKey.decode(der.segment(), der.length());
                }
            } else {
                decoded = OpenSslSigningKey.decode(encoded.segment(), encoded.length());
            }
        }
        try {
            String type;
            if (decoded.is("RSA")) {
                type = "RSA";
            } else if (decoded.is("EC")) {
                type = "EC";
            } else if (decoded.is("ED25519")) {
                type = "Ed25519";
            } else {
                throw new IllegalArgumentException("the private key is neither RSA, EC nor "
                        + "Ed25519");
            }
            PublicKey publicKey = KeyFactory.getInstance(type)
                    .generatePublic(new X509EncodedKeySpec(decoded.publicKey()));
            return new NativeKey(type, publicKey, decoded);
        } catch (GeneralSecurityException | RuntimeException e) {
            decoded.close();
            if (e instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw new IllegalStateException("the public half of the key could not be read", e);
        }
    }

    /**
     * Signs {@code message} (public) with {@code digest}; with {@code pss},
     * RSA-PSS with MGF1 of the same digest and a salt as long as it.
     *
     * @return the signature - DER for ECDSA, as JCA has it
     */
    byte[] sign(String digest, boolean pss, byte[] message, int length) {
        lock.readLock().lock();
        try {
            if (destroyed) {
                throw new IllegalStateException("this key has been destroyed");
            }
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment data = arena.allocate(Math.max(1, length));
                MemorySegment.copy(message, 0, data, ValueLayout.JAVA_BYTE, 0, length);
                MemorySegment out = arena.allocate(OpenSslSigningKey.MAX_SIGNATURE);
                int written = key.sign(digest, pss, data, length, out);
                return out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE);
            }
        } finally {
            lock.readLock().unlock();
        }
    }

    void destroy() {
        lock.writeLock().lock();
        try {
            if (!destroyed) {
                destroyed = true;
                key.close();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    boolean isDestroyed() {
        lock.readLock().lock();
        try {
            return destroyed;
        } finally {
            lock.readLock().unlock();
        }
    }
}
