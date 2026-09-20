package space.seclume.oracle.auth;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import space.seclume.crypto.Aes;
import space.seclume.crypto.AesKey;
import space.seclume.crypto.HashAlgorithm;

/**
 * The key derivation of the Oracle login (O5LOGON), 11g path.
 *
 * <p>The procedure, as far as it is documented (see {@code PROVENANCE.md}):
 *
 * <ol>
 *   <li>The server sends {@code AUTH_SESSKEY} - its session key,
 *       encrypted - and {@code AUTH_VFR_DATA}, the salt.</li>
 *   <li>The client computes {@code SHA1(password || salt)}, twenty bytes, and
 *       pads with zero bytes to twenty-four. That is the
 *       AES-192 key.</li>
 *   <li>With it {@code AUTH_SESSKEY} is decrypted: AES-192 in CBC mode with a
 *       zero IV.</li>
 * </ol>
 *
 * <p>Padding with zeroes is not sloppiness on this implementation's part but
 * what the protocol does - and the reason the scheme became known as
 * CVE-2012-3137: the server hands out the encrypted session key <b>before</b>
 * it has checked the password, and whoever captures it can try passwords
 * offline. A client can do nothing about that; all it can do is make sure the
 * password is left lying around nowhere on its side.
 *
 * <p>That is exactly what this class delivers: password and salt come in as
 * {@link MemorySegment}, and the derived key along with every intermediate step
 * lives off-heap and is zeroed.
 */
public final class O5Login {

    /** Length of the derived AES key: 192 bits. */
    public static final int KEY_LENGTH = 24;
    /** The hash yields 20 bytes; the remaining four are zeroes. */
    private static final int SHA1_LENGTH = 20;

    private O5Login() {
    }

    /**
     * Derives the AES-192 key from password and salt.
     *
     * @param out target for {@link #KEY_LENGTH} bytes
     */
    public static void deriveKey(MemorySegment password, long passwordOffset, int passwordLength,
                                 MemorySegment salt, long saltOffset, int saltLength,
                                 MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment combined = arena.allocate(passwordLength + saltLength);
            try {
                MemorySegment.copy(password, passwordOffset, combined, 0, passwordLength);
                MemorySegment.copy(salt, saltOffset, combined, passwordLength, saltLength);
                HashAlgorithm.SHA_1.hash(combined, 0, combined.byteSize(), out, outOffset);
                // The four missing bytes are zeroes - the scheme requires it.
                out.asSlice(outOffset + SHA1_LENGTH, KEY_LENGTH - SHA1_LENGTH).fill((byte) 0);
            } finally {
                combined.fill((byte) 0);
            }
        }
    }

    /**
     * Decrypts the server session key.
     *
     * <p>AES-192 in CBC mode with a zero IV. A zero IV is normally a mistake;
     * here it is part of the protocol, and making it "right" would mean not
     * being able to log in.
     *
     * @param sessionKey the encrypted {@code AUTH_SESSKEY} of the server
     * @param out        target, at least as large as {@code length}
     */
    public static void decryptSessionKey(MemorySegment key, long keyOffset,
                                         MemorySegment sessionKey, long sessionKeyOffset,
                                         int length, MemorySegment out, long outOffset) {
        if (length % 16 != 0) {
            throw new IllegalArgumentException(
                    "AUTH_SESSKEY is " + length + " bytes; AES needs a multiple of 16");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment iv = arena.allocate(Aes.BLOCK);  // zero IV, as the protocol wants
            try (AesKey aesKey = new AesKey(key, keyOffset, KEY_LENGTH)) {
                Aes.cbcDecrypt(aesKey, iv, sessionKey, sessionKeyOffset, out, outOffset, length);
            } finally {
                iv.fill((byte) 0);
            }
        }
    }
}
