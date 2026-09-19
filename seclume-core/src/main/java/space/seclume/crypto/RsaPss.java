package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * RSASSA-PSS signature verification (RFC 8017, sections 8.1.2 and 9.1.2) -
 * the scheme every RSA certificate in TLS 1.3 signs with
 * ({@code rsa_pss_rsae_*}; RSASSA-PKCS1-v1_5 is for the certificate itself,
 * never for a live handshake signature). TLS 1.3 fixes the salt length to the
 * hash length (RFC 8446, section 4.2.3), so that is not a parameter here.
 *
 * <p>Verification only - this driver signs nothing with PSS itself, and
 * unused crypto is one more place to be wrong.
 *
 * <p><b>Assumes the modulus's top bit is set</b> - true of every RSA key this
 * has been tested against, and how key generation actually behaves for a
 * requested bit length, but not a guarantee DER makes on its own. A modulus
 * one bit short of a whole byte would need a narrower top-byte mask than the
 * one used here; that case is not handled.
 */
public final class RsaPss {

    private static final int TRAILER = 0xbc;

    private RsaPss() {
    }

    /**
     * Verifies an {@code rsa_pss_rsae_*} signature over {@code message}.
     *
     * @param message the exact bytes that were signed - not a hash of them,
     *                {@link #verify} hashes them itself
     */
    public static boolean verify(RsaPublicKey key, HashAlgorithm hash,
            MemorySegment message, long messageOffset, int messageLength,
            MemorySegment signature, long signatureOffset, int signatureLength) {
        int emLen = key.modulusBytes();
        if (signatureLength != emLen) {
            return false;                     // a signature not shaped for this key is not this key's
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment em = arena.allocate(emLen);
            try {
                Rsa.publicOperation(key, signature, signatureOffset, em, 0);
                return verifyEncoded(hash, message, messageOffset, messageLength, em, emLen);
            } finally {
                em.fill((byte) 0);            // not a secret, but nothing here needs to linger either
            }
        }
    }

    /** EMSA-PSS-VERIFY (RFC 8017, section 9.1.2), given the recovered {@code m = s^e mod n}. */
    private static boolean verifyEncoded(HashAlgorithm hash, MemorySegment message,
            long messageOffset, int messageLength, MemorySegment em, int emLen) {
        int hLen = hash.digestLength();
        int sLen = hLen;                      // TLS 1.3: salt length == hash length, always
        int topByteMask = 0x7f;               // see the class note on the top-bit assumption

        if (emLen < hLen + sLen + 2) {
            return false;
        }
        if ((em.get(ValueLayout.JAVA_BYTE, emLen - 1) & 0xff) != TRAILER) {
            return false;
        }

        int maskedDbLen = emLen - hLen - 1;
        MemorySegment h = em.asSlice(maskedDbLen, hLen);
        if ((em.get(ValueLayout.JAVA_BYTE, 0) & ~topByteMask) != 0) {
            return false;
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment db = arena.allocate(maskedDbLen);
            Rsa.mgf1(hash, h, 0, hLen, db, maskedDbLen);
            for (int i = 0; i < maskedDbLen; i++) {
                byte masked = em.get(ValueLayout.JAVA_BYTE, i);
                byte unmasked = (byte) (masked ^ db.get(ValueLayout.JAVA_BYTE, i));
                db.set(ValueLayout.JAVA_BYTE, i, unmasked);
            }
            db.set(ValueLayout.JAVA_BYTE, 0, (byte) (db.get(ValueLayout.JAVA_BYTE, 0) & topByteMask));

            int psLen = maskedDbLen - sLen - 1;
            for (int i = 0; i < psLen; i++) {
                if (db.get(ValueLayout.JAVA_BYTE, i) != 0) {
                    return false;
                }
            }
            if ((db.get(ValueLayout.JAVA_BYTE, psLen) & 0xff) != 0x01) {
                return false;
            }
            MemorySegment salt = db.asSlice(psLen + 1, sLen);

            // M' = eight zero bytes, mHash, salt; H' = Hash(M'); compare with H.
            try (Digest digest = hash.newDigest()) {
                MemorySegment zeros = arena.allocate(8);            // already zero-filled
                MemorySegment mHash = arena.allocate(hLen);
                hash.hash(message, messageOffset, messageLength, mHash, 0);
                digest.update(zeros, 0, 8);
                digest.update(mHash, 0, hLen);
                digest.update(salt, 0, sLen);
                MemorySegment hPrime = arena.allocate(hLen);
                digest.digest(hPrime, 0);
                return ConstantTime.equals(h, 0, hPrime, 0, hLen);
            }
        }
    }
}
