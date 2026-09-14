package space.seclume.postgresql.auth;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;

/**
 * PostgreSQL's {@code md5} authentication, off-heap.
 *
 * <p>The scheme is long obsolete and switched off in newer servers - but every
 * legacy server that has not been moved to {@code scram-sha-256} yet demands
 * it. Leave it out and you cannot log in there.
 *
 * <p>What is computed is
 * {@code "md5" + hex(md5(hex(md5(password + user)) + salt))}. The intermediate
 * values are as good as the password itself - whoever has them can log in - so
 * they live off-heap as well and are zeroed.
 */
public final class Md5Password {

    /** Length of the finished answer: "md5" plus 32 hex chars plus a zero byte. */
    public static final int RESPONSE_LENGTH = 3 + 32 + 1;

    private static final byte[] HEX = "0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: a public constant alphabet, no secret

    private Md5Password() {
    }

    /**
     * Writes the finished answer including the zero byte into {@code target}.
     *
     * @param password the password, off-heap
     * @param user     the user name, off-heap (no secret, but it goes into the
     *                 same hash)
     * @param salt     the four bytes from the server's request
     * @return the number of bytes written
     */
    public static int response(MemorySegment password, MemorySegment user, MemorySegment salt,
                               MemorySegment target) {
        try (Arena arena = Arena.ofConfined();
             Digest md5 = HashAlgorithm.MD5.newDigest()) {
            MemorySegment inner = arena.allocate(16);
            MemorySegment innerHex = arena.allocate(32);
            MemorySegment outer = arena.allocate(16);
            try {
                md5.update(password);
                md5.update(user);
                md5.digest(inner, 0);
                hex(inner, innerHex);

                md5.update(innerHex, 0, 32);
                md5.update(salt, 0, 4);
                md5.digest(outer, 0);

                target.set(ValueLayout.JAVA_BYTE, 0, (byte) 'm');
                target.set(ValueLayout.JAVA_BYTE, 1, (byte) 'd');
                target.set(ValueLayout.JAVA_BYTE, 2, (byte) '5');
                hex(outer, target.asSlice(3, 32));
                target.set(ValueLayout.JAVA_BYTE, 35, (byte) 0);
                return RESPONSE_LENGTH;
            } finally {
                inner.fill((byte) 0);
                innerHex.fill((byte) 0);
                outer.fill((byte) 0);
            }
        }
    }

    /** 16 bytes to 32 hex chars, off-heap; {@code HexFormat} works on Strings. */
    private static void hex(MemorySegment source, MemorySegment target) {
        for (int i = 0; i < 16; i++) {
            int value = source.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            target.set(ValueLayout.JAVA_BYTE, i * 2L, HEX[value >>> 4]);
            target.set(ValueLayout.JAVA_BYTE, i * 2L + 1, HEX[value & 0x0f]);
        }
    }
}
