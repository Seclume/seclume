package space.seclume.oracle.auth;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.Aes;
import space.seclume.crypto.AesKey;
import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Pbkdf2;

/**
 * Logging in to a <b>newer</b> Oracle instance: O5LOGON with the
 * 12C-Verifier ({@code 0x4815}).
 *
 * <p>This is not the special case but the normal one. Since 12.1 this verifier
 * has been the default, and current servers have
 * {@code SQLNET.ALLOWED_LOGON_VERSION_SERVER=12} - where the old 11g verifiers
 * are usually not permitted at all any more. Anyone setting up an instance
 * today (19c, 21c, 23ai) gets this path.
 *
 * <p>The procedure, derived from python-oracledb v4.0.2 (see
 * {@code docs/protocol/oracle.md} - which also carries the licence and what
 * was derived from which file):
 *
 * <ol>
 *   <li><b>Password hash.</b> PBKDF2-HMAC-SHA512 over the password, with the
 *       salt {@code AUTH_VFR_DATA || "AUTH_PBKDF2_SPEEDY_KEY"} and the round
 *       count the server names as {@code AUTH_PBKDF2_VGEN_COUNT}; 64 bytes come
 *       out. Then SHA-512 over that together with {@code AUTH_VFR_DATA}, and
 *       the first 32 bytes are the hash.</li>
 *   <li><b>Session key.</b> With it the server's {@code AUTH_SESSKEY} is
 *       decrypted (AES-CBC, zero IV): 48 bytes. The client rolls 48 bytes of
 *       its own.</li>
 *   <li><b>Combo key.</b> Bytes 16 to 40 of both halves
 *       are XORed - 24 bytes. Then MD5 over the first 16 and MD5 over the
 *       remaining 8; the two results one after the other, truncated to 32
 *       bytes.</li>
 *   <li><b>{@code AUTH_PASSWORD}.</b> Sixteen random bytes in front of the
 *       password, the whole thing AES-CBC encrypted with the combo key and sent
 *       as upper-case hex.</li>
 * </ol>
 *
 * <p>All of this runs off-heap here. With Oracle that matters especially: the
 * server hands out {@code AUTH_SESSKEY} <b>before</b> it has checked the
 * password (CVE-2012-3137). A capture allows offline attacks - what a client
 * can do about that is nothing; what it can do is make sure nothing is left
 * lying around on its own side.
 */
public final class O5Login12c {

    /** Verifier type 12C, as newer servers report it. */
    public static final int VERIFIER_TYPE = 0x4815;
    /** Verifier type 11g, variant 1 - old, here only for recognition. */
    public static final int VERIFIER_TYPE_11G_1 = 0xb152;
    /** Verifier type 11g, variant 2 - old, here only for recognition. */
    public static final int VERIFIER_TYPE_11G_2 = 0x1b25;

    /** Length of the password hash and thus of the AES key: 256 bits. */
    public static final int PASSWORD_HASH_LENGTH = 32;
    /** Length of the derived PBKDF2 output. */
    public static final int DERIVED_LENGTH = 64;
    /** Length of the session keys on both sides. */
    public static final int SESSION_KEY_LENGTH = 48;
    /** Length of the combo key with the 12C verifier. */
    public static final int COMBO_KEY_LENGTH = 32;
    /** This many random bytes stand in front of the password. */
    public static final int PASSWORD_SALT_LENGTH = 16;

    /** The fixed suffix Oracle appends to the salt. */
    private static final byte[] SPEEDY_KEY =
            "AUTH_PBKDF2_SPEEDY_KEY".getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: a fixed public protocol constant, no secret

    private O5Login12c() {
    }

    /**
     * The password hash - the AES key {@code AUTH_SESSKEY} is decrypted
     * with.
     *
     * @param verifierData the server's {@code AUTH_VFR_DATA}
     * @param iterations   the server's {@code AUTH_PBKDF2_VGEN_COUNT}
     * @param out          target for {@link #PASSWORD_HASH_LENGTH} bytes
     */
    public static void passwordHash(MemorySegment password, long passwordOffset,
                                    int passwordLength,
                                    MemorySegment verifierData, long verifierOffset,
                                    int verifierLength,
                                    int iterations, MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(Math.max(passwordLength, 1));
            MemorySegment salt = arena.allocate(verifierLength + SPEEDY_KEY.length);
            MemorySegment derived = arena.allocate(DERIVED_LENGTH);
            MemorySegment digest = arena.allocate(HashAlgorithm.SHA_512.digestLength());
            try {
                MemorySegment.copy(password, passwordOffset, secret, 0, passwordLength);
                MemorySegment.copy(verifierData, verifierOffset, salt, 0, verifierLength);
                MemorySegment.copy(MemorySegment.ofArray(SPEEDY_KEY), 0, salt,
                        verifierLength, SPEEDY_KEY.length);

                Pbkdf2.derive(HashAlgorithm.SHA_512, secret.asSlice(0, passwordLength),
                        salt, iterations, derived);

                try (Digest sha512 = HashAlgorithm.SHA_512.newDigest()) {
                    sha512.update(derived, 0, DERIVED_LENGTH);
                    sha512.update(verifierData, verifierOffset, verifierLength);
                    sha512.digest(digest, 0);
                }
                MemorySegment.copy(digest, 0, out, outOffset, PASSWORD_HASH_LENGTH);
            } finally {
                secret.fill((byte) 0);
                salt.fill((byte) 0);
                derived.fill((byte) 0);
                digest.fill((byte) 0);
            }
        }
    }

    /** The session key length newer servers use - and the older one is 48. */
    public static final int SESSION_KEY_LENGTH_32 = 32;

    /**
     * The expensive step on its own: PBKDF2 over the password.
     *
     * <p>Kept apart from {@link #passwordHash} because the 64 bytes are needed
     * twice - once for the hash, and once as the content of
     * {@code AUTH_PBKDF2_SPEEDY_KEY}, with which the server can check the
     * password on later connections without doing these 4096 rounds again.
     *
     * @param out target for {@link #DERIVED_LENGTH} bytes
     */
    public static void passwordKey(MemorySegment password, long passwordOffset,
                                   int passwordLength,
                                   MemorySegment verifierData, long verifierOffset,
                                   int verifierLength,
                                   int iterations, MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(Math.max(passwordLength, 1));
            MemorySegment salt = arena.allocate(verifierLength + SPEEDY_KEY.length);
            try {
                MemorySegment.copy(password, passwordOffset, secret, 0, passwordLength);
                MemorySegment.copy(verifierData, verifierOffset, salt, 0, verifierLength);
                MemorySegment.copy(MemorySegment.ofArray(SPEEDY_KEY), 0, salt,
                        verifierLength, SPEEDY_KEY.length);
                Pbkdf2.derive(HashAlgorithm.SHA_512, secret.asSlice(0, passwordLength),
                        salt, iterations, out.asSlice(outOffset, DERIVED_LENGTH));
            } finally {
                secret.fill((byte) 0);
                salt.fill((byte) 0);
            }
        }
    }

    /**
     * The password hash from an already derived password key.
     *
     * @param out target for {@link #PASSWORD_HASH_LENGTH} bytes
     */
    public static void passwordHashFrom(MemorySegment passwordKey, long keyOffset,
                                        MemorySegment verifierData, long verifierOffset,
                                        int verifierLength,
                                        MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment digest = arena.allocate(HashAlgorithm.SHA_512.digestLength());
            try {
                try (Digest sha512 = HashAlgorithm.SHA_512.newDigest()) {
                    sha512.update(passwordKey, keyOffset, DERIVED_LENGTH);
                    sha512.update(verifierData, verifierOffset, verifierLength);
                    sha512.digest(digest, 0);
                }
                MemorySegment.copy(digest, 0, out, outOffset, PASSWORD_HASH_LENGTH);
            } finally {
                digest.fill((byte) 0);
            }
        }
    }

    /** Decrypts a session key of the given length; the IV is zero. */
    public static void decryptSessionKey(MemorySegment passwordHash, long hashOffset,
                                         MemorySegment sessionKey, long sessionKeyOffset,
                                         int length, MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment iv = arena.allocate(Aes.BLOCK);
            try (AesKey key = new AesKey(passwordHash, hashOffset, PASSWORD_HASH_LENGTH)) {
                Aes.cbcDecrypt(key, iv, sessionKey, sessionKeyOffset, out, outOffset, length);
            } finally {
                iv.fill((byte) 0);
            }
        }
    }

    /**
     * Encrypts the client's half of the session key with the password hash.
     *
     * <p>No padding: the length is a multiple of the block size, and the
     * server only reads as many bytes as it expects anyway.
     */
    public static void encryptSessionKey(MemorySegment passwordHash, long hashOffset,
                                         MemorySegment clientKey, long clientOffset,
                                         int length, MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment iv = arena.allocate(Aes.BLOCK);
            try (AesKey key = new AesKey(passwordHash, hashOffset, PASSWORD_HASH_LENGTH)) {
                Aes.cbcEncrypt(key, iv, clientKey, clientOffset, out, outOffset, length);
            } finally {
                iv.fill((byte) 0);
            }
        }
    }

    /**
     * The combo key of the 32-byte variant.
     *
     * <p>Different from the 48-byte one in every respect, and the difference
     * is not a detail: the two halves are not XORed but <b>written out as
     * upper-case hex text</b> - client half first - and that text is then run
     * through PBKDF2 with the server's {@code AUTH_PBKDF2_CSK_SALT}. Three
     * rounds, not four thousand: the expensive step has already happened, this
     * one only mixes in the session.
     *
     * <p>Established by measurement, not by reading: the recorded handshake
     * contains every value except the password, so the right derivation is the
     * one that turns {@code AUTH_PASSWORD} back into the known password. See
     * {@code docs/protocol/oracle.md} and {@code docs/protocol/oracle.md}.
     *
     * @param out target for {@link #COMBO_KEY_LENGTH} bytes
     */
    public static void comboKey32(MemorySegment clientKey, long clientOffset,
                                  MemorySegment serverKey, long serverOffset,
                                  MemorySegment salt, long saltOffset, int saltLength,
                                  int iterations, MemorySegment out, long outOffset) {
        int half = SESSION_KEY_LENGTH_32;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = arena.allocate(half * 4L);
            MemorySegment saltCopy = arena.allocate(Math.max(saltLength, 1));
            try {
                toUpperHex(clientKey.asSlice(clientOffset, half), half, text, 0);
                toUpperHex(serverKey.asSlice(serverOffset, half), half, text, half * 2L);
                MemorySegment.copy(salt, saltOffset, saltCopy, 0, saltLength);
                Pbkdf2.derive(HashAlgorithm.SHA_512, text, saltCopy, iterations,
                        out.asSlice(outOffset, COMBO_KEY_LENGTH));
            } finally {
                text.fill((byte) 0);
                saltCopy.fill((byte) 0);
            }
        }
    }

    /** Decrypts {@code AUTH_SESSKEY} with the password hash. */
    public static void decryptSessionKey(MemorySegment passwordHash, long hashOffset,
                                         MemorySegment sessionKey, long sessionKeyOffset,
                                         MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment iv = arena.allocate(Aes.BLOCK);
            try (AesKey key = new AesKey(passwordHash, hashOffset, PASSWORD_HASH_LENGTH)) {
                Aes.cbcDecrypt(key, iv, sessionKey, sessionKeyOffset, out, outOffset,
                        SESSION_KEY_LENGTH);
            } finally {
                iv.fill((byte) 0);
            }
        }
    }

    /**
     * The combo key made from both session keys.
     *
     * <p>Only bytes 16 to 40 go in - the first sixteen stay unused. The
     * protocol does not say why; it just is so, and a client that folds in all
     * 48 bytes does not get in.
     */
    public static void comboKey(MemorySegment serverKey, long serverOffset,
                                MemorySegment clientKey, long clientOffset,
                                MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment mixed = arena.allocate(24);
            MemorySegment first = arena.allocate(16);
            MemorySegment second = arena.allocate(16);
            try {
                for (int i = 0; i < 24; i++) {
                    byte a = serverKey.get(ValueLayout.JAVA_BYTE, serverOffset + 16 + i);
                    byte b = clientKey.get(ValueLayout.JAVA_BYTE, clientOffset + 16 + i);
                    mixed.set(ValueLayout.JAVA_BYTE, i, (byte) (a ^ b));
                }
                HashAlgorithm.MD5.hash(mixed, 0, 16, first, 0);
                HashAlgorithm.MD5.hash(mixed, 16, 8, second, 0);
                // The two results one after the other are 32 bytes - exactly
                // the length the 12C verifier wants.
                MemorySegment.copy(first, 0, out, outOffset, 16);
                MemorySegment.copy(second, 0, out, outOffset + 16, COMBO_KEY_LENGTH - 16);
            } finally {
                mixed.fill((byte) 0);
                first.fill((byte) 0);
                second.fill((byte) 0);
            }
        }
    }

    /**
     * Builds {@code AUTH_PASSWORD}: salt, password, AES-CBC, upper-case hex.
     *
     * <p>Padding follows PKCS#7, that is {@code n} bytes of the value
     * {@code n} - even when the length already fits. That matters: padding
     * "only when needed" would be ambiguous and would be rejected for
     * block-aligned passwords.
     *
     * @param salt 16 random bytes; the caller rolls them
     * @param out  target for the hex text; needs
     *             {@code 2 * (16 + password length rounded up to 16)} bytes
     * @return the length of the hex text written
     */
    public static int encryptedPassword(MemorySegment comboKey, long comboOffset,
                                        MemorySegment password, long passwordOffset,
                                        int passwordLength,
                                        MemorySegment salt, long saltOffset,
                                        MemorySegment out, long outOffset) {
        int plainLength = PASSWORD_SALT_LENGTH + passwordLength;
        int padding = Aes.BLOCK - (plainLength % Aes.BLOCK);
        int paddedLength = plainLength + padding;

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment plain = arena.allocate(paddedLength);
            MemorySegment cipher = arena.allocate(paddedLength);
            MemorySegment iv = arena.allocate(Aes.BLOCK);
            try {
                MemorySegment.copy(salt, saltOffset, plain, 0, PASSWORD_SALT_LENGTH);
                MemorySegment.copy(password, passwordOffset, plain, PASSWORD_SALT_LENGTH,
                        passwordLength);
                plain.asSlice(plainLength, padding).fill((byte) padding);

                try (AesKey key = new AesKey(comboKey, comboOffset, COMBO_KEY_LENGTH)) {
                    Aes.cbcEncrypt(key, iv, plain, 0, cipher, 0, paddedLength);
                }
                return toUpperHex(cipher, paddedLength, out, outOffset);
            } finally {
                plain.fill((byte) 0);
                cipher.fill((byte) 0);
                iv.fill((byte) 0);
            }
        }
    }

    /** Upper-case hex, off-heap - {@code HexFormat} would run through Strings. */
    private static int toUpperHex(MemorySegment source, int length,
                                  MemorySegment out, long outOffset) {
        for (int i = 0; i < length; i++) {
            int value = source.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            out.set(ValueLayout.JAVA_BYTE, outOffset + i * 2L, hexDigit(value >>> 4));
            out.set(ValueLayout.JAVA_BYTE, outOffset + i * 2L + 1, hexDigit(value & 0x0f));
        }
        return length * 2;
    }

    private static byte hexDigit(int value) {
        return (byte) (value < 10 ? '0' + value : 'A' + value - 10);
    }
}
