package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.atomic.AtomicBoolean;

/** {@link AesGcm} behind {@link AesGcmCipher}: constant time, portable, slow. */
final class JavaAesGcm implements AesGcmCipher {

    private static final System.Logger LOG = System.getLogger(AesGcmCipher.class.getName());
    private static final AtomicBoolean WARNED = new AtomicBoolean();

    private final AesKey key;

    JavaAesGcm(MemorySegment key, long offset, int length) {
        this.key = new AesKey(key, offset, length);
    }

    @Override
    public void encrypt(MemorySegment nonce, long nonceOffset, MemorySegment aad, long aadOffset,
                        long aadLength, MemorySegment in, long inOffset, long length,
                        MemorySegment out, long outOffset) {
        AesGcm.encrypt(key, nonce, nonceOffset, aad, aadOffset, aadLength, in, inOffset, length,
                out, outOffset);
    }

    @Override
    public boolean decrypt(MemorySegment nonce, long nonceOffset, MemorySegment aad,
                           long aadOffset, long aadLength, MemorySegment in, long inOffset,
                           long length, MemorySegment out, long outOffset) {
        return AesGcm.decrypt(key, nonce, nonceOffset, aad, aadOffset, aadLength, in, inOffset,
                length, out, outOffset);
    }

    /**
     * Says once per JVM that TLS records go through this one - far slower
     * than OpenSSL or CNG (RecordBenchmark) - and why. Not when
     * {@code seclume.crypto.aesGcm=java} asked for it.
     */
    static void warnOnce(String reason, Throwable cause) {
        if (WARNED.compareAndSet(false, true)) {
            LOG.log(System.Logger.Level.WARNING, "AES-GCM runs in Java here, constant time "
                    + "but hundreds of times slower than native for bulk data: " + reason
                    + " (tlsStack=jsse, the default, does not use it)", cause);
        }
    }

    @Override
    public String implementation() {
        return "java";
    }

    @Override
    public void close() {
        key.close();
    }
}
