package space.seclume.mysql.auth;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.SecureRandom;

import space.seclume.crypto.Ed25519;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Pbkdf2;

/**
 * MariaDB's two logins by signature, where the server stores only a public
 * key and a stolen {@code mysql.global_priv} does not let anyone log in.
 *
 * <ul>
 *   <li>{@code client_ed25519} (MariaDB 10.1.22+): the server sends 32 random
 *       bytes; the client answers with their Ed25519 signature under the key
 *       expanded from the password itself - SHA-512 of the password, of any
 *       length, where RFC 8032 would expand a 32-byte seed.</li>
 *   <li>{@code parsec} (MariaDB 11.6+): the server sends 32 random bytes; the
 *       client asks for the "ext-salt" with an empty packet and gets the KDF
 *       ({@code P} for PBKDF2-SHA-512), its iteration factor (1024 shifted by
 *       it) and the salt. The client derives a 32-byte seed from password and
 *       salt, draws 32 random bytes of its own, and sends them with the
 *       signature over both scrambles - a standard Ed25519 key this time.</li>
 * </ul>
 *
 * <p>Both run on {@link Ed25519}: the expanded key, the derived seed and every
 * intermediate value live in native memory and are zeroed.
 */
public final class Ed25519Login {

    /** The client side of MariaDB's {@code ed25519} plugin. */
    public static final String CLIENT_ED25519 = "client_ed25519";
    /** The client side of MariaDB's {@code parsec} plugin. */
    public static final String PARSEC = "parsec";
    /** The server's scramble for both. */
    public static final int SCRAMBLE_LENGTH = 32;
    /** {@code client_ed25519}'s answer: the signature. */
    public static final int ED25519_RESPONSE_LENGTH = Ed25519.SIGNATURE_LENGTH;
    /** {@code parsec}'s answer: the client's scramble and the signature. */
    public static final int PARSEC_RESPONSE_LENGTH = SCRAMBLE_LENGTH + Ed25519.SIGNATURE_LENGTH;

    private static final int SEED_LENGTH = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Ed25519Login() {
    }

    /** Whether {@code plugin} is one of the two. */
    public static boolean handles(String plugin) {
        return CLIENT_ED25519.equals(plugin) || PARSEC.equals(plugin);
    }

    /**
     * {@code client_ed25519}: the signature of the server's scramble.
     *
     * @return {@link #ED25519_RESPONSE_LENGTH}
     */
    public static int ed25519Response(MemorySegment password, long passwordOffset,
                                      int passwordLength, MemorySegment scramble,
                                      long scrambleOffset, MemorySegment out, long outOffset) {
        Ed25519.sign(password, passwordOffset, passwordLength, scramble, scrambleOffset,
                SCRAMBLE_LENGTH, out, outOffset);
        return ED25519_RESPONSE_LENGTH;
    }

    /**
     * {@code parsec}: the client's scramble and the signature of both.
     *
     * @param extSalt the server's answer to the empty packet: KDF, iteration
     *                factor, salt
     * @return {@link #PARSEC_RESPONSE_LENGTH}
     * @throws IllegalArgumentException for an ext-salt this client does not
     *         know, or one that asks for fewer than 1024 or absurdly many
     *         iterations
     */
    public static int parsecResponse(MemorySegment password, long passwordOffset,
                                     int passwordLength, MemorySegment scramble,
                                     long scrambleOffset, MemorySegment extSalt,
                                     long extSaltOffset, int extSaltLength,
                                     MemorySegment out, long outOffset) {
        if (extSaltLength < 3) {
            throw new IllegalArgumentException("the server's ext-salt has " + extSaltLength
                    + " bytes, too few for a KDF, an iteration count and a salt");
        }
        int kdf = extSalt.get(ValueLayout.JAVA_BYTE, extSaltOffset) & 0xff;
        if (kdf != 'P') {
            throw new IllegalArgumentException("the server's ext-salt names the KDF '"
                    + (char) kdf + "'; this client knows only 'P' (PBKDF2)");
        }
        int factor = extSalt.get(ValueLayout.JAVA_BYTE, extSaltOffset + 1) & 0xff;
        if (factor >= '0' && factor <= '9') {
            factor -= '0';
        }
        if (factor > 10) {
            throw new IllegalArgumentException("the server's ext-salt asks for 1024 << "
                    + factor + " iterations");
        }
        int iterations = 1024 << factor;
        int saltLength = extSaltLength - 2;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seed = arena.allocate(SEED_LENGTH);
            MemorySegment scrambles = arena.allocate(2 * SCRAMBLE_LENGTH);
            try {
                MemorySegment secret = password.asSlice(passwordOffset, passwordLength);
                MemorySegment salt = extSalt.asSlice(extSaltOffset + 2, saltLength);
                Pbkdf2.derive(HashAlgorithm.SHA_512, secret, salt, iterations, seed);
                byte[] own = new byte[SCRAMBLE_LENGTH]; // seclume-allow: the client's scramble, sent in the clear
                RANDOM.nextBytes(own);
                MemorySegment.copy(scramble, scrambleOffset, scrambles, 0, SCRAMBLE_LENGTH);
                MemorySegment.copy(own, 0, scrambles, ValueLayout.JAVA_BYTE, SCRAMBLE_LENGTH,
                        SCRAMBLE_LENGTH);
                MemorySegment.copy(own, 0, out, ValueLayout.JAVA_BYTE, outOffset, SCRAMBLE_LENGTH);
                Ed25519.sign(seed, 0, SEED_LENGTH, scrambles, 0, 2 * SCRAMBLE_LENGTH,
                        out, outOffset + SCRAMBLE_LENGTH);
                return PARSEC_RESPONSE_LENGTH;
            } finally {
                seed.fill((byte) 0);
            }
        }
    }
}
