package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Platform;
import space.seclume.secret.SecretScope;

/**
 * An ephemeral P-256 key owned by CNG (Windows) or OpenSSL 3 (64-bit Linux).
 * No private scalar, shared secret, or intermediate field arithmetic is passed
 * through a Java array or JCA key. There is no heap-based fallback.
 *
 * <p>The provider owns and destroys its private key. Our temporary secret buffer
 * is wiped by SecretScope, including on failure; the caller owns and must wipe
 * the derived output. Provider memory is outside the Java heap, but is not
 * promised to be locked against swapping. This does not protect a process dump.
 *
 * <p>Thread-confined, explicitly closed, and not a migration format. The TLS
 * handshake must destroy this key once its shared secret has been consumed.
 */
public final class NativeP256 implements AutoCloseable {
    public static final int PUBLIC_SIZE = 65;
    public static final int SECRET_SIZE = 32;

    interface Backend extends AutoCloseable {
        void publicKey(MemorySegment out);
        void derive(MemorySegment peer, MemorySegment out);
        void privateScalar(MemorySegment out);
        @Override void close();
    }

    private final Thread owner = Thread.currentThread();
    private final Backend backend;
    private boolean closed;

    private NativeP256(Backend backend) {
        this.backend = backend;
    }

    /** Generates the private key and its entropy entirely inside the provider. */
    public static NativeP256 generate() {
        return new NativeP256(create(null, null));
    }

    private static Backend create(MemorySegment point, MemorySegment scalar) {
        if (Platform.isWindows()) {
            return new CngP256(point, scalar);
        }
        if (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8) {
            return new OpenSslP256(point, scalar);
        }
        throw new UnsupportedOperationException("native P-256 requires Windows or 64-bit Linux with libcrypto.so.3");
    }

    /** Writes 0x04 || x || y, two 32-byte big-endian coordinates. */
    public void publicKey(MemorySegment out) {
        checkOpen();
        writableNative(out, PUBLIC_SIZE);
        backend.publicKey(out);
    }

    /**
     * Validates the peer point and writes the 32-byte, big-endian shared x coordinate.
     * Output is left untouched on failure. Both arguments must be native segments;
     * the peer is an uncompressed P-256 point. No KDF is applied here.
     */
    public void derive(MemorySegment peer, MemorySegment out) {
        checkOpen();
        publicPoint(peer);
        writableNative(out, SECRET_SIZE);
        try (SecretScope secret = SecretScope.allocate(SECRET_SIZE)) {
            backend.derive(peer, secret.segment());
            MemorySegment.copy(secret.segment(), 0, out, 0, SECRET_SIZE);
        }
    }

    // Package-private hooks for published vectors and the separate heap probe.
    // Application callers generate keys; they never need to export a scalar.
    static NativeP256 importKey(MemorySegment point, MemorySegment scalar) {
        publicPoint(point);
        nativeSize(scalar, SECRET_SIZE);
        return new NativeP256(create(point, scalar));
    }

    void privateScalar(MemorySegment out) {
        checkOpen();
        writableNative(out, SECRET_SIZE);
        try (SecretScope secret = SecretScope.allocate(SECRET_SIZE)) {
            backend.privateScalar(secret.segment());
            MemorySegment.copy(secret.segment(), 0, out, 0, SECRET_SIZE);
        }
    }

    private static void publicPoint(MemorySegment point) {
        nativeSize(point, PUBLIC_SIZE);
        if (point.get(ValueLayout.JAVA_BYTE, 0) != 4) {
            throw new IllegalArgumentException("P-256 requires an uncompressed public point");
        }
    }

    private static void nativeSize(MemorySegment segment, int size) {
        if (!segment.isNative() || segment.byteSize() != size) {
            throw new IllegalArgumentException("expected a native segment of " + size + " bytes");
        }
        if (!segment.scope().isAlive() || !segment.isAccessibleBy(Thread.currentThread())) {
            throw new IllegalStateException("segment is closed or belongs to another thread");
        }
    }

    private static void writableNative(MemorySegment segment, int size) {
        nativeSize(segment, size);
        if (segment.isReadOnly()) {
            throw new IllegalArgumentException("output is read-only");
        }
    }

    private void checkThread() {
        if (Thread.currentThread() != owner) {
            throw new IllegalStateException("P-256 key belongs to another thread");
        }
    }

    private void checkOpen() {
        checkThread();
        if (closed) {
            throw new IllegalStateException("P-256 key is closed");
        }
    }

    @Override
    public void close() {
        checkThread();
        if (!closed) {
            closed = true;
            backend.close();
        }
    }
}
