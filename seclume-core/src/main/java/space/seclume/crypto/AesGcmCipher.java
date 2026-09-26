package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Platform;

/**
 * AES-GCM with one key, for as many messages as a TLS connection sends.
 *
 * <p>Where the platform has it, the work is the operating system's crypto
 * library: OpenSSL's EVP on Linux, CNG on Windows - the same libraries the TLS
 * stack already needs for P-256. Both run AES in hardware (AES-NI) or in
 * constant-time software, so the key never meets a lookup table indexed by a
 * secret, and they are an order of magnitude faster than anything written in
 * Java here. The key goes from native memory into the library's own key
 * object and is never on the heap.
 *
 * <p>Everywhere else - or if the library cannot be loaded - {@link AesGcm},
 * whose AES is constant time as well (see {@link AesSubBytes}), only slower.
 * {@link #implementation()} says which one a connection got.
 */
public interface AesGcmCipher extends AutoCloseable {

    /**
     * Encrypts {@code length} bytes and writes the ciphertext and then the
     * {@link AesGcm#TAG}-byte tag to {@code out}.
     */
    void encrypt(MemorySegment nonce, long nonceOffset,
                 MemorySegment aad, long aadOffset, long aadLength,
                 MemorySegment in, long inOffset, long length,
                 MemorySegment out, long outOffset);

    /**
     * Decrypts {@code length} bytes of ciphertext, followed in {@code in} by
     * the tag. Returns false - and leaves {@code out} zeroed - when the tag
     * does not match.
     */
    boolean decrypt(MemorySegment nonce, long nonceOffset,
                    MemorySegment aad, long aadOffset, long aadLength,
                    MemorySegment in, long inOffset, long length,
                    MemorySegment out, long outOffset);

    /** {@code openssl}, {@code cng} or {@code java}. */
    String implementation();

    /** Destroys the key. */
    @Override
    void close();

    /** A cipher for a 16- or 32-byte key: native where possible, see above. */
    static AesGcmCipher of(MemorySegment key, long offset, int length) {
        if (length != 16 && length != 32) {
            throw new IllegalArgumentException("AES-GCM takes a 16 or 32 byte key, not " + length);
        }
        if (!"java".equals(System.getProperty("seclume.crypto.aesGcm"))) {
            try {
                if (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8) {
                    return new OpenSslAesGcm(key, offset, length);
                }
                if (Platform.isWindows()) {
                    return new CngAesGcm(key, offset, length);
                }
                JavaAesGcm.warnOnce("there is no native AES-GCM for this platform", null);
            } catch (LinkageError | RuntimeException unavailable) {
                // no usable library - the constant-time Java version below
                JavaAesGcm.warnOnce("the native AES-GCM could not be loaded", unavailable);
            }
        }
        return new JavaAesGcm(key, offset, length);
    }
}
