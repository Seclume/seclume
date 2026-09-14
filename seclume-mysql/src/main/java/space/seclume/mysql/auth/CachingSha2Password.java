package space.seclume.mysql.auth;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Rsa;
import space.seclume.crypto.RsaPublicKey;

/**
 * {@code caching_sha2_password} - the default method since MySQL 8.
 *
 * <p>It has two paths:
 *
 * <ol>
 *   <li><b>Fast path.</b> The client sends
 *       {@code SHA256(password) XOR SHA256(SHA256(SHA256(password)) || scramble)},
 *       32 bytes. That only works when the server has the user in its cache -
 *       hence the name. If it answers {@code 0x03}, the login is done.</li>
 *   <li><b>Full path.</b> If it answers {@code 0x04}, it does not know the user
 *       yet and needs the password in the clear. Over TLS it goes straight out
 *       (zero-terminated). Without TLS the client fetches the server's public
 *       key and encrypts with it - see {@link #encryptedPassword}.</li>
 * </ol>
 *
 * <p>The fast path is not an attack surface: the server stores a salted
 * SHA-256, not the value the client sends - unlike with
 * {@code mysql_native_password}, the cache content is of no use to an
 * attacker.
 *
 * <p>Both paths run entirely off-heap here, the encryption included: the
 * modular exponentiation works on a native word array, not on
 * {@code BigInteger} - which would be immutable, would sit on the heap and
 * could not be zeroed.
 */
public final class CachingSha2Password {

    /** Length of the answer on the fast path. */
    public static final int RESPONSE_LENGTH = 32;
    public static final int SCRAMBLE_LENGTH = 20;

    /** The server has the user in its cache - done. */
    public static final int FAST_AUTH_SUCCESS = 0x03;
    /** The server needs the password in the clear or encrypted. */
    public static final int FULL_AUTH_REQUIRED = 0x04;
    /** A request for the server's public key. */
    public static final byte REQUEST_PUBLIC_KEY = 0x02;

    private CachingSha2Password() {
    }

    /**
     * The answer for the fast path.
     *
     * @return {@link #RESPONSE_LENGTH}, or 0 for an empty password
     */
    public static int response(MemorySegment password, long passwordOffset, int passwordLength,
                               MemorySegment scramble, long scrambleOffset,
                               MemorySegment out, long outOffset) {
        if (passwordLength == 0) {
            return 0;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment stage1 = arena.allocate(RESPONSE_LENGTH);
            MemorySegment stage2 = arena.allocate(RESPONSE_LENGTH);
            try {
                // SHA256(password)
                HashAlgorithm.SHA_256.hash(password, passwordOffset, passwordLength, stage1, 0);
                // SHA256(SHA256(password))
                HashAlgorithm.SHA_256.hash(stage1, 0, RESPONSE_LENGTH, stage2, 0);
                // SHA256(SHA256(SHA256(password)) || scramble)
                try (Digest digest = HashAlgorithm.SHA_256.newDigest()) {
                    digest.update(stage2, 0, RESPONSE_LENGTH);
                    digest.update(scramble, scrambleOffset, SCRAMBLE_LENGTH);
                    digest.digest(stage2, 0);
                }
                for (int i = 0; i < RESPONSE_LENGTH; i++) {
                    byte value = (byte) (stage1.get(ValueLayout.JAVA_BYTE, i)
                            ^ stage2.get(ValueLayout.JAVA_BYTE, i));
                    out.set(ValueLayout.JAVA_BYTE, outOffset + i, value);
                }
                return RESPONSE_LENGTH;
            } finally {
                stage1.fill((byte) 0);
                stage2.fill((byte) 0);
            }
        }
    }

    /**
     * The encrypted password for the full path without TLS.
     *
     * <p>The client XORs the zero-terminated password with the scramble - the
     * scramble repeating as needed - and encrypts the result with the server's
     * public key. The XOR is not encryption and is not meant to be; it makes
     * sure the same password twice does not yield the same ciphertext, even
     * should the padding ever weaken.
     *
     * @param hash the OAEP hash; MySQL uses SHA-1, newer servers can do SHA-256
     * @return the length of the ciphertext ({@code key.modulusBytes()})
     */
    public static int encryptedPassword(RsaPublicKey key, HashAlgorithm hash,
                                        MemorySegment password, long passwordOffset,
                                        int passwordLength,
                                        MemorySegment scramble, long scrambleOffset,
                                        MemorySegment out, long outOffset) {
        int length = passwordLength + 1;   // mit Abschlussnull
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment masked = arena.allocate(length);
            try {
                MemorySegment.copy(password, passwordOffset, masked, 0, passwordLength);
                masked.set(ValueLayout.JAVA_BYTE, passwordLength, (byte) 0);
                for (int i = 0; i < length; i++) {
                    byte scrambleByte = scramble.get(ValueLayout.JAVA_BYTE,
                            scrambleOffset + (i % SCRAMBLE_LENGTH));
                    masked.set(ValueLayout.JAVA_BYTE, i,
                            (byte) (masked.get(ValueLayout.JAVA_BYTE, i) ^ scrambleByte));
                }
                return Rsa.encryptOaep(key, hash, masked, 0, length, out, outOffset);
            } finally {
                masked.fill((byte) 0);
            }
        }
    }

    /**
     * The password in the clear, zero-terminated - the full path over TLS.
     *
     * <p>Cleartext is right here and not careless: the line is encrypted, and
     * the server has to see the password itself in order to fill its cache. It
     * still does not leave native memory.
     */
    public static int clearPassword(MemorySegment password, long passwordOffset,
                                    int passwordLength, MemorySegment out, long outOffset) {
        MemorySegment.copy(password, passwordOffset, out, outOffset, passwordLength);
        out.set(ValueLayout.JAVA_BYTE, outOffset + passwordLength, (byte) 0);
        return passwordLength + 1;
    }
}
