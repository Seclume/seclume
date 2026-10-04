package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Platform;
import space.seclume.secret.SecretScope;

/**
 * An ephemeral key for one of the TLS key exchange groups this project speaks:
 * P-256, P-384 and X25519 - owned by CNG (Windows) or OpenSSL 3 (64-bit Linux),
 * like {@link NativeP256}, which carries P-256 here. No private key and no
 * shared secret passes through a Java array or a JCA key.
 *
 * <p>Public keys are in their TLS encoding: an uncompressed point
 * ({@code 0x04 || x || y}) for the two NIST curves, the 32-byte little-endian
 * u-coordinate of RFC 7748 for X25519. The shared secret is the x-coordinate
 * for the curves and the X25519 output; an all-zero X25519 result - a peer
 * that sent a low-order point - is refused (RFC 8446 section 7.4.2).
 *
 * <p>Thread-confined and explicitly closed, as {@code NativeP256} is.
 */
public final class NativeEcdh implements AutoCloseable {

    /** A group, with its TLS id and its sizes. */
    public enum Group {
        P256(0x0017, NativeP256.PUBLIC_SIZE, NativeP256.SECRET_SIZE, "P-256"),
        P384(0x0018, 97, 48, "P-384"),
        X25519(0x001d, 32, 32, "X25519");

        private final int id;
        private final int publicSize;
        private final int secretSize;
        private final String label;

        Group(int id, int publicSize, int secretSize, String label) {
            this.id = id;
            this.publicSize = publicSize;
            this.secretSize = secretSize;
            this.label = label;
        }

        /** The TLS NamedGroup. */
        public int id() {
            return id;
        }

        public int publicSize() {
            return publicSize;
        }

        public int secretSize() {
            return secretSize;
        }

        @Override
        public String toString() {
            return label;
        }

        /** The group for a TLS NamedGroup, or null for one this project does not speak. */
        public static Group of(int id) {
            for (Group group : values()) {
                if (group.id == id) {
                    return group;
                }
            }
            return null;
        }
    }

    interface Backend extends AutoCloseable {
        void publicKey(MemorySegment out);

        void derive(MemorySegment peer, MemorySegment out);

        @Override
        void close();
    }

    private final Thread owner = Thread.currentThread();
    private final Group group;
    private final Backend backend;
    private boolean closed;

    private NativeEcdh(Group group, Backend backend) {
        this.group = group;
        this.backend = backend;
    }

    /** Generates a key for {@code group}, entirely inside the provider. */
    public static NativeEcdh generate(Group group) {
        if (group == Group.P256) {
            NativeP256 key = NativeP256.generate();
            return new NativeEcdh(group, new Backend() {
                @Override
                public void publicKey(MemorySegment out) {
                    key.publicKey(out);
                }

                @Override
                public void derive(MemorySegment peer, MemorySegment out) {
                    key.derive(peer, out);
                }

                @Override
                public void close() {
                    key.close();
                }
            });
        }
        if (Platform.isWindows()) {
            return new NativeEcdh(group, new CngEcdh(group));
        }
        if (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8) {
            return new NativeEcdh(group, new OpenSslEcdh(group));
        }
        throw new UnsupportedOperationException("native " + group
                + " requires Windows or 64-bit Linux with libcrypto.so.3");
    }

    public Group group() {
        return group;
    }

    /** Writes this key's public key in its TLS encoding - {@code group().publicSize()} bytes. */
    public void publicKey(MemorySegment out) {
        checkOpen();
        nativeSize(out, group.publicSize());
        backend.publicKey(out);
    }

    /**
     * Validates the peer's public key and writes the shared secret -
     * {@code group().secretSize()} bytes. Output is left untouched on failure.
     */
    public void derive(MemorySegment peer, MemorySegment out) {
        checkOpen();
        nativeSize(peer, group.publicSize());
        nativeSize(out, group.secretSize());
        if (group != Group.X25519 && peer.get(ValueLayout.JAVA_BYTE, 0) != 4) {
            throw new IllegalArgumentException(group + " requires an uncompressed public point");
        }
        int size = group.secretSize();
        try (SecretScope secret = SecretScope.allocate(size)) {
            MemorySegment bytes = secret.segment().asSlice(0, size);
            backend.derive(peer, bytes);
            if (group == Group.X25519) {
                int any = 0;
                for (int i = 0; i < size; i++) {
                    any |= bytes.get(ValueLayout.JAVA_BYTE, i);
                }
                if (any == 0) {
                    throw new IllegalArgumentException("the peer's X25519 key is a low-order point");
                }
            }
            MemorySegment.copy(bytes, 0, out, 0, size);
        }
    }

    private static void nativeSize(MemorySegment segment, int size) {
        if (!segment.isNative() || segment.byteSize() != size) {
            throw new IllegalArgumentException("expected a native segment of " + size + " bytes");
        }
    }

    private void checkOpen() {
        if (Thread.currentThread() != owner) {
            throw new IllegalStateException("this key belongs to another thread");
        }
        if (closed) {
            throw new IllegalStateException("this key is closed");
        }
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            backend.close();
        }
    }
}
