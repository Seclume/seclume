package space.seclume.crypto;

import java.lang.foreign.MemorySegment;

/** {@link AesGcm} behind {@link AesGcmCipher}: constant time, portable, slow. */
final class JavaAesGcm implements AesGcmCipher {

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

    @Override
    public String implementation() {
        return "java";
    }

    @Override
    public void close() {
        key.close();
    }
}
