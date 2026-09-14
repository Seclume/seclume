package space.seclume.mysql.auth;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;

/**
 * {@code mysql_native_password} - the old method, in place since MySQL 4.1.
 *
 * <p>The answer is
 * {@code SHA1(password) XOR SHA1(scramble || SHA1(SHA1(password)))}, that is
 * twenty bytes. The server knows {@code SHA1(SHA1(password))}, can compute the
 * right-hand side from it and recover {@code SHA1(password)} by XOR; hashing
 * that once more has to yield the stored value.
 *
 * <p>The method is weak - whoever knows the stored value can log in without the
 * password - but it is widespread, and a driver that cannot do it gets past
 * many legacy servers.
 *
 * <p>All three hashes and the XOR run on {@link MemorySegment} here. A
 * {@code byte[20]} holding {@code SHA1(password)} would be as good as the
 * password itself: with it alone one can log in.
 */
public final class NativePassword {

    /** Length of the answer and of every intermediate step. */
    public static final int RESPONSE_LENGTH = 20;
    /** Length of the scramble the server sends in the handshake. */
    public static final int SCRAMBLE_LENGTH = 20;

    private NativePassword() {
    }

    /**
     * Computes the answer.
     *
     * @param password  the password in native memory, UTF-8
     * @param scramble  the twenty bytes from the handshake
     * @param out       target for the twenty bytes of the answer
     * @return {@link #RESPONSE_LENGTH}, or 0 for an empty password - then the
     *         protocol sends an empty answer
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
            MemorySegment combined = arena.allocate(SCRAMBLE_LENGTH + RESPONSE_LENGTH);
            try {
                // SHA1(password)
                HashAlgorithm.SHA_1.hash(password, passwordOffset, passwordLength, stage1, 0);
                // SHA1(SHA1(password))
                HashAlgorithm.SHA_1.hash(stage1, 0, RESPONSE_LENGTH, stage2, 0);
                // SHA1(scramble || SHA1(SHA1(password)))
                MemorySegment.copy(scramble, scrambleOffset, combined, 0, SCRAMBLE_LENGTH);
                MemorySegment.copy(stage2, 0, combined, SCRAMBLE_LENGTH, RESPONSE_LENGTH);
                try (Digest digest = HashAlgorithm.SHA_1.newDigest()) {
                    digest.update(combined, 0, combined.byteSize());
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
                combined.fill((byte) 0);
            }
        }
    }
}
