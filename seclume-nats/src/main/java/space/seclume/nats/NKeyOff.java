package space.seclume.nats;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import space.seclume.crypto.Ed25519;

/**
 * NATS NKey seeds and {@code .creds} files decoded and signed in native memory.
 *
 * <p>A NATS seed is Base32 (RFC 4648 without padding) over two prefix bytes,
 * the 32-byte Ed25519 seed (or 64 bytes when the public key is appended), and a
 * little-endian CRC-16/XMODEM checksum. A {@code .creds} file wraps a user JWT
 * and a seed in {@code -----BEGIN ...-----} blocks.
 *
 * <p>The official client's {@code NKey} and {@code FileAuthHandler} decode the
 * seed into a {@code char[]} and a {@code byte[]} on the heap. Here the Base32
 * decoding, the CRC-16 check, the public-key derivation and the Ed25519
 * signature all run in a confined {@link Arena} that is zeroed before it
 * closes; only the public key (a {@code U...} string) and the 64-byte signature
 * ever reach the heap.
 */
final class NKeyOff {

    private static final int PREFIX_BYTE_SEED = 18 << 3;
    private static final int PREFIX_BYTE_PRIVATE = 15 << 3;
    private static final int PREFIX_BYTE_SERVER = 13 << 3;
    private static final int PREFIX_BYTE_CLUSTER = 2 << 3;
    private static final int PREFIX_BYTE_ACCOUNT = 0;
    private static final int PREFIX_BYTE_USER = 20 << 3;
    private static final int PREFIX_BYTE_OPERATOR = 14 << 3;

    private static final int SEED_LENGTH = 32;

    private NKeyOff() {
    }

    /**
     * Derives the encoded NATS public key (for example {@code U...}) from a
     * raw NKey seed or a {@code .creds} file in {@code source}.
     */
    static char[] publicKey(MemorySegment source, int length) { // seclume-allow: the public key (U...) - public by definition
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seed = arena.allocate(SEED_LENGTH);
            MemorySegment pub = arena.allocate(Ed25519.PUBLIC_KEY_LENGTH);
            MemorySegment framed = arena.allocate(1 + Ed25519.PUBLIC_KEY_LENGTH + 2);
            try {
                int prefix = extractSeed(source, length, seed, arena);
                Ed25519.publicKey(seed, 0, SEED_LENGTH, pub, 0);
                framed.set(JAVA_BYTE, 0, (byte) prefix);
                MemorySegment.copy(pub, 0, framed, 1, Ed25519.PUBLIC_KEY_LENGTH);
                int crc = crc16(framed, 0, 1 + Ed25519.PUBLIC_KEY_LENGTH);
                framed.set(JAVA_BYTE, 1 + Ed25519.PUBLIC_KEY_LENGTH, (byte) (crc & 0xff));
                framed.set(JAVA_BYTE, 1 + Ed25519.PUBLIC_KEY_LENGTH + 1, (byte) ((crc >>> 8) & 0xff));
                return base32EncodePublic(framed, 1 + Ed25519.PUBLIC_KEY_LENGTH + 2);
            } finally {
                seed.fill((byte) 0);
                pub.fill((byte) 0);
                framed.fill((byte) 0);
            }
        }
    }

    /**
     * Signs {@code nonce} with the Ed25519 seed held in {@code source} (a bare
     * NKey seed or a {@code .creds} file) and returns the 64-byte signature.
     */
    static byte[] sign(MemorySegment source, int length, byte[] nonce) {
        if (nonce == null) {
            throw new IllegalArgumentException("nonce is null");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seed = arena.allocate(SEED_LENGTH);
            MemorySegment msg = arena.allocate(nonce.length);
            MemorySegment sig = arena.allocate(Ed25519.SIGNATURE_LENGTH);
            try {
                extractSeed(source, length, seed, arena);
                MemorySegment.copy(nonce, 0, msg, JAVA_BYTE, 0, nonce.length);
                Ed25519.sign(seed, 0, SEED_LENGTH, msg, 0, nonce.length, sig, 0);
                return sig.toArray(JAVA_BYTE);
            } finally {
                seed.fill((byte) 0);
            }
        }
    }

    /**
     * Extracts the user JWT from a {@code .creds} or JWT buffer, or returns
     * {@code null} when {@code source} holds only a bare NKey seed.
     */
    static char[] extractJwt(MemorySegment source, int length) { // seclume-allow: the user JWT is public; the seed stays in native memory
        int[] span = PemSpan.findBlock(source, length, "NATS USER JWT");
        if (span == null) {
            return null;
        }
        return readTokenChars(source, span[0], span[1]);
    }

    /**
     * Extracts the user JWT from a dedicated JWT secret source (either wrapped
     * in {@code -----BEGIN NATS USER JWT-----} or a bare JWT).
     */
    static char[] extractStandaloneJwt(MemorySegment source, int length) { // seclume-allow: a standalone user JWT is public
        int[] span = PemSpan.findBlock(source, length, "NATS USER JWT");
        if (span != null) {
            return readTokenChars(source, span[0], span[1]);
        }
        int[] token = PemSpan.firstToken(source, 0, length);
        if (token == null) {
            throw new IllegalArgumentException("no JWT found in the JWT source");
        }
        return readTokenChars(source, token[0], token[1]);
    }

    private static char[] readTokenChars(MemorySegment source, int from, int to) { // seclume-allow: reads the public JWT characters
        int count = 0;
        for (int i = from; i < to; i++) {
            byte b = source.get(JAVA_BYTE, i);
            if (!isWhitespace(b)) {
                count++;
            }
        }
        char[] out = new char[count]; // seclume-allow: the public user JWT
        int p = 0;
        for (int i = from; i < to; i++) {
            byte b = source.get(JAVA_BYTE, i);
            if (!isWhitespace(b)) {
                out[p++] = (char) (b & 0xff);
            }
        }
        return out;
    }

    /**
     * Finds the NKey seed in {@code source} (either inside a
     * {@code -----BEGIN ... NKEY SEED-----} block or as a bare Base32 token),
     * verifies its prefix and CRC-16, copies the 32-byte Ed25519 seed into
     * {@code seedOut}, and returns the public prefix byte.
     */
    private static int extractSeed(MemorySegment source, int length,
                                   MemorySegment seedOut, Arena arena) {
        int[] span = PemSpan.findSeedBlock(source, length);
        if (span == null) {
            span = PemSpan.firstToken(source, 0, length);
        }
        if (span == null || span[1] <= span[0]) {
            throw new IllegalArgumentException("no NATS NKey seed found");
        }
        int encodedLen = span[1] - span[0];
        int maxDecoded = (encodedLen * 5) / 8 + 4;
        MemorySegment raw = arena.allocate(maxDecoded);
        try {
            int rawLen = base32DecodeOff(source, span[0], span[1], raw);
            if (rawLen != 2 + 32 + 2 && rawLen != 2 + 64 + 2) {
                throw new IllegalArgumentException("not a valid NATS NKey seed length ("
                        + rawLen + " decoded bytes)");
            }
            int expectedCrc = (raw.get(JAVA_BYTE, rawLen - 2) & 0xff)
                    | ((raw.get(JAVA_BYTE, rawLen - 1) & 0xff) << 8);
            int actualCrc = crc16(raw, 0, rawLen - 2);
            if (actualCrc != expectedCrc) {
                throw new IllegalArgumentException("NATS NKey seed CRC-16 check failed");
            }
            int b0 = raw.get(JAVA_BYTE, 0) & 0xff;
            int b1 = raw.get(JAVA_BYTE, 1) & 0xff;
            int prefixKind = b0 & 248;
            int publicPrefix = ((b0 & 7) << 5) | ((b1 & 248) >>> 3);
            if (prefixKind != PREFIX_BYTE_SEED) {
                throw new IllegalArgumentException("not a NATS NKey seed (starts with prefix "
                        + prefixKind + ")");
            }
            if (!isValidPublicPrefix(publicPrefix)) {
                throw new IllegalArgumentException("unknown NATS NKey public prefix: "
                        + publicPrefix);
            }
            MemorySegment.copy(raw, 2, seedOut, 0, SEED_LENGTH);
            return publicPrefix;
        } finally {
            raw.fill((byte) 0);
        }
    }

    private static boolean isValidPublicPrefix(int prefix) {
        return prefix == PREFIX_BYTE_USER
                || prefix == PREFIX_BYTE_ACCOUNT
                || prefix == PREFIX_BYTE_OPERATOR
                || prefix == PREFIX_BYTE_SERVER
                || prefix == PREFIX_BYTE_CLUSTER
                || prefix == PREFIX_BYTE_PRIVATE;
    }

    /**
     * Constant-time Base32 (RFC 4648) decoding in native memory without lookup
     * tables indexed by secret values.
     */
    private static int base32DecodeOff(MemorySegment source, int from, int to,
                                       MemorySegment target) {
        int buffer = 0;
        int bitsLeft = 0;
        int out = 0;
        for (int i = from; i < to; i++) {
            int c = source.get(JAVA_BYTE, i) & 0xff;
            if (c == '=' || isWhitespace((byte) c)) {
                continue;
            }
            int val = base32Value(c);
            if (val < 0) {
                throw new IllegalArgumentException("not a Base32 character in NKey seed at offset "
                        + (i - from));
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                target.set(JAVA_BYTE, out++, (byte) (buffer >>> bitsLeft));
            }
        }
        return out;
    }

    /** Constant-time RFC 4648 Base32 character value (A-Z -> 0..25, 2-7 -> 26..31), or -1. */
    private static int base32Value(int c) {
        int upper = inRange(c, 'A', 'Z');
        int lower = inRange(c, 'a', 'z');
        int digit = inRange(c, '2', '7');
        int value = (upper & (c - 'A'))
                | (lower & (c - 'a'))
                | (digit & (c - '2' + 26));
        int valid = upper | lower | digit;
        return value | ~valid;
    }

    private static int inRange(int c, int low, int high) {
        return ~(((c - low) | (high - c)) >> 31);
    }

    /** Encodes the public key frame (prefix + 32-byte public key + 2-byte CRC) as Base32. */
    private static char[] base32EncodePublic(MemorySegment input, int length) { // seclume-allow: encodes the public key (U...)
        char[] out = new char[(length * 8 + 4) / 5]; // seclume-allow: the public key
        int offset = 0;
        int buffer = input.get(JAVA_BYTE, offset++) & 0xff;
        int bitsLeft = 8;
        int i = 0;
        while (bitsLeft > 0 || offset < length) {
            if (bitsLeft < 5) {
                if (offset < length) {
                    buffer = (buffer << 8) | (input.get(JAVA_BYTE, offset++) & 0xff);
                    bitsLeft += 8;
                } else {
                    int pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }
            int index = (buffer >>> (bitsLeft - 5)) & 0x1f;
            bitsLeft -= 5;
            out[i++] = (char) (index < 26 ? ('A' + index) : ('2' + (index - 26)));
        }
        return out;
    }

    /** CRC-16/XMODEM (poly 0x1021, init 0x0000) computed bitwise without a table. */
    static int crc16(MemorySegment data, long offset, int length) {
        int crc = 0;
        for (int i = 0; i < length; i++) {
            crc ^= (data.get(JAVA_BYTE, offset + i) & 0xff) << 8;
            for (int bit = 0; bit < 8; bit++) {
                int mask = -((crc >>> 15) & 1);
                crc = ((crc << 1) ^ (0x1021 & mask)) & 0xffff;
            }
        }
        return crc;
    }

    static boolean isWhitespace(byte b) {
        return b == ' ' || b == '\t' || b == '\r' || b == '\n';
    }
}
