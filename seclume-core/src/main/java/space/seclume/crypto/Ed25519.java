package space.seclume.crypto;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Ed25519 signing (RFC 8032) on native memory - the one curve computed here
 * rather than handed to OpenSSL or CNG.
 *
 * <p>The exception, and why: MariaDB's two key-based logins sign with a key
 * that comes from the password. {@code client_ed25519} expands the password
 * itself, of any length, with SHA-512 where RFC 8032 expands a 32-byte seed -
 * no library takes that. {@code parsec} derives a standard seed, but CNG has
 * no Ed25519 at all. So the choice was an own signature or no such login on
 * Windows and none of {@code client_ed25519} anywhere. Only signing is here;
 * nothing is verified with this class.
 *
 * <p>How: field elements mod 2^255 - 19 as sixteen 16-bit limbs in 64-bit
 * words, points in extended coordinates, the base point multiplied by a
 * Montgomery-style ladder that does the same additions for every bit and
 * swaps by mask - the structure of TweetNaCl (public domain). Every value
 * that depends on the key - the expanded key, the nonce, the intermediate
 * points, the scalar products - lives in one confined arena that is zeroed
 * before it is freed; the heap sees only the signature, which is public.
 *
 * <p>Checked against the RFC 8032 vectors and against the JDK's own Ed25519
 * (see {@code Ed25519Test}).
 */
public final class Ed25519 {

    /** Length of a signature: R and S. */
    public static final int SIGNATURE_LENGTH = 64;
    /** Length of a public key. */
    public static final int PUBLIC_KEY_LENGTH = 32;

    private static final int LIMBS = 16;
    private static final long GF = LIMBS * 8L;

    private static final long[] D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a,
        0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
    private static final long[] BASE_X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760,
        0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
    private static final long[] BASE_Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
    /** The group order L, little-endian bytes. */
    private static final long[] ORDER = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6,
        0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

    private Ed25519() {
    }

    /**
     * Signs {@code message} with the key expanded from {@code seed}: RFC 8032
     * when the seed is 32 bytes, MariaDB's {@code client_ed25519} when it is
     * the password.
     *
     * @param signature 64 bytes are written at {@code signatureOffset}
     */
    public static void sign(MemorySegment seed, long seedOffset, long seedLength,
                            MemorySegment message, long messageOffset, long messageLength,
                            MemorySegment signature, long signatureOffset) {
        try (Work w = new Work()) {
            MemorySegment az = w.bytes(64);
            MemorySegment nonce = w.bytes(64);
            MemorySegment hram = w.bytes(64);
            MemorySegment publicKey = w.bytes(PUBLIC_KEY_LENGTH);
            MemorySegment r = w.bytes(PUBLIC_KEY_LENGTH);

            HashAlgorithm.SHA_512.hash(seed, seedOffset, seedLength, az, 0);
            az.set(JAVA_BYTE, 0, (byte) (az.get(JAVA_BYTE, 0) & 248));
            az.set(JAVA_BYTE, 31, (byte) ((az.get(JAVA_BYTE, 31) & 127) | 64));

            // A = a * B
            w.scalarBase(az, publicKey);

            // r = H(prefix || M) mod L, R = r * B
            try (Digest digest = HashAlgorithm.SHA_512.newDigest()) {
                digest.update(az, 32, 32);
                digest.update(message, messageOffset, messageLength);
                digest.digest(nonce, 0);
            }
            w.reduce(nonce);
            w.scalarBase(nonce, r);

            // k = H(R || A || M) mod L
            try (Digest digest = HashAlgorithm.SHA_512.newDigest()) {
                digest.update(r, 0, 32);
                digest.update(publicKey, 0, 32);
                digest.update(message, messageOffset, messageLength);
                digest.digest(hram, 0);
            }
            w.reduce(hram);

            // S = (r + k * a) mod L
            MemorySegment x = w.longs(64);
            for (int i = 0; i < 32; i++) {
                x.setAtIndex(JAVA_LONG, i, nonce.get(JAVA_BYTE, i) & 0xffL);
            }
            for (int i = 0; i < 32; i++) {
                long k = hram.get(JAVA_BYTE, i) & 0xffL;
                for (int j = 0; j < 32; j++) {
                    long v = x.getAtIndex(JAVA_LONG, i + j) + k * (az.get(JAVA_BYTE, j) & 0xffL);
                    x.setAtIndex(JAVA_LONG, i + j, v);
                }
            }
            MemorySegment.copy(r, 0, signature, signatureOffset, 32);
            modL(signature, signatureOffset + 32, x);
        }
    }

    /**
     * The public key of {@code seed}, expanded as in {@link #sign} - for tests
     * and for the server side of a key registration, not needed to log in.
     */
    public static void publicKey(MemorySegment seed, long seedOffset, long seedLength,
                                 MemorySegment out, long outOffset) {
        try (Work w = new Work()) {
            MemorySegment az = w.bytes(64);
            HashAlgorithm.SHA_512.hash(seed, seedOffset, seedLength, az, 0);
            az.set(JAVA_BYTE, 0, (byte) (az.get(JAVA_BYTE, 0) & 248));
            az.set(JAVA_BYTE, 31, (byte) ((az.get(JAVA_BYTE, 31) & 127) | 64));
            MemorySegment publicKey = w.bytes(PUBLIC_KEY_LENGTH);
            w.scalarBase(az, publicKey);
            MemorySegment.copy(publicKey, 0, out, outOffset, PUBLIC_KEY_LENGTH);
        }
    }

    /** {@code x} (64 words, a product of scalars) mod L into 32 bytes at {@code out}. */
    private static void modL(MemorySegment out, long outOffset, MemorySegment x) {
        for (int i = 63; i >= 32; i--) {
            long carry = 0;
            int j;
            long xi = x.getAtIndex(JAVA_LONG, i);
            for (j = i - 32; j < i - 12; j++) {
                long v = x.getAtIndex(JAVA_LONG, j) + carry - 16 * xi * ORDER[j - (i - 32)];
                carry = (v + 128) >> 8;
                x.setAtIndex(JAVA_LONG, j, v - (carry << 8));
            }
            x.setAtIndex(JAVA_LONG, j, x.getAtIndex(JAVA_LONG, j) + carry);
            x.setAtIndex(JAVA_LONG, i, 0);
        }
        long carry = 0;
        long top = x.getAtIndex(JAVA_LONG, 31) >> 4;
        for (int j = 0; j < 32; j++) {
            long v = x.getAtIndex(JAVA_LONG, j) + carry - top * ORDER[j];
            carry = v >> 8;
            x.setAtIndex(JAVA_LONG, j, v & 255);
        }
        for (int j = 0; j < 32; j++) {
            x.setAtIndex(JAVA_LONG, j, x.getAtIndex(JAVA_LONG, j) - carry * ORDER[j]);
        }
        for (int i = 0; i < 32; i++) {
            long v = x.getAtIndex(JAVA_LONG, i);
            x.setAtIndex(JAVA_LONG, i + 1, x.getAtIndex(JAVA_LONG, i + 1) + (v >> 8));
            out.set(JAVA_BYTE, outOffset + i, (byte) (v & 255));
        }
    }

    /**
     * One signature's worth of native memory, zeroed when closed, and the
     * field and point arithmetic that works in it.
     */
    private static final class Work implements AutoCloseable {

        private final Arena arena = Arena.ofConfined();
        private final java.util.List<MemorySegment> allocated = new java.util.ArrayList<>();
        /** The 31 words of a product before reduction. */
        private final MemorySegment product = longs(31);
        private final MemorySegment packed = bytes(32);
        private final MemorySegment packT = gf();
        private final MemorySegment packM = gf();
        private final MemorySegment a = gf();
        private final MemorySegment b = gf();
        private final MemorySegment c = gf();
        private final MemorySegment d = gf();
        private final MemorySegment e = gf();
        private final MemorySegment f = gf();
        private final MemorySegment g = gf();
        private final MemorySegment h = gf();
        private final MemorySegment t = gf();
        private final MemorySegment d2 = constant(D2);
        private final MemorySegment one = gf();

        Work() {
            one.setAtIndex(JAVA_LONG, 0, 1);
        }

        MemorySegment bytes(long length) {
            MemorySegment segment = arena.allocate(length, 8);
            allocated.add(segment);
            return segment;
        }

        MemorySegment longs(int count) {
            return bytes(count * 8L);
        }

        MemorySegment gf() {
            return bytes(GF);
        }

        MemorySegment constant(long[] limbs) {
            MemorySegment segment = gf();
            MemorySegment.copy(limbs, 0, segment, JAVA_LONG, 0, LIMBS);
            return segment;
        }

        /** 64 bytes, a hash, reduced mod L into its first 32; the rest zeroed. */
        void reduce(MemorySegment r) {
            MemorySegment x = longs(64);
            for (int i = 0; i < 64; i++) {
                x.setAtIndex(JAVA_LONG, i, r.get(JAVA_BYTE, i) & 0xffL);
            }
            r.fill((byte) 0);
            modL(r, 0, x);
        }

        /** {@code s} (32 bytes) times the base point, encoded into {@code out}. */
        void scalarBase(MemorySegment s, MemorySegment out) {
            MemorySegment[] p = point();
            MemorySegment[] q = point();
            MemorySegment.copy(BASE_X, 0, q[0], JAVA_LONG, 0, LIMBS);
            MemorySegment.copy(BASE_Y, 0, q[1], JAVA_LONG, 0, LIMBS);
            copy(q[2], one);
            mul(q[3], q[0], q[1]);
            // The neutral element (0, 1, 1, 0).
            copy(p[1], one);
            copy(p[2], one);
            for (int i = 255; i >= 0; i--) {
                int bit = (s.get(JAVA_BYTE, i >>> 3) >>> (i & 7)) & 1;
                swap(p, q, bit);
                add(q, p);
                add(p, p);
                swap(p, q, bit);
            }
            pack(out, p);
        }

        MemorySegment[] point() {
            return new MemorySegment[] {gf(), gf(), gf(), gf()};
        }

        /** p += q, extended coordinates (add-2008-hwcd-3). */
        void add(MemorySegment[] p, MemorySegment[] q) {
            sub(a, p[1], p[0]);
            sub(t, q[1], q[0]);
            mul(a, a, t);
            sum(b, p[0], p[1]);
            sum(t, q[0], q[1]);
            mul(b, b, t);
            mul(c, p[3], q[3]);
            mul(c, c, d2);
            mul(d, p[2], q[2]);
            sum(d, d, d);
            sub(e, b, a);
            sub(f, d, c);
            sum(g, d, c);
            sum(h, b, a);
            mul(p[0], e, f);
            mul(p[1], h, g);
            mul(p[2], g, f);
            mul(p[3], e, h);
        }

        void swap(MemorySegment[] p, MemorySegment[] q, int bit) {
            for (int i = 0; i < 4; i++) {
                select(p[i], q[i], bit);
            }
        }

        /** Swaps p and q when {@code bit} is 1, by mask. */
        static void select(MemorySegment p, MemorySegment q, int bit) {
            long mask = -(long) bit;
            for (int i = 0; i < LIMBS; i++) {
                long pi = p.getAtIndex(JAVA_LONG, i);
                long qi = q.getAtIndex(JAVA_LONG, i);
                long x = mask & (pi ^ qi);
                p.setAtIndex(JAVA_LONG, i, pi ^ x);
                q.setAtIndex(JAVA_LONG, i, qi ^ x);
            }
        }

        static void copy(MemorySegment to, MemorySegment from) {
            MemorySegment.copy(from, 0, to, 0, GF);
        }

        static void sum(MemorySegment o, MemorySegment x, MemorySegment y) {
            for (int i = 0; i < LIMBS; i++) {
                o.setAtIndex(JAVA_LONG, i, x.getAtIndex(JAVA_LONG, i) + y.getAtIndex(JAVA_LONG, i));
            }
        }

        static void sub(MemorySegment o, MemorySegment x, MemorySegment y) {
            for (int i = 0; i < LIMBS; i++) {
                o.setAtIndex(JAVA_LONG, i, x.getAtIndex(JAVA_LONG, i) - y.getAtIndex(JAVA_LONG, i));
            }
        }

        void mul(MemorySegment o, MemorySegment x, MemorySegment y) {
            product.fill((byte) 0);
            for (int i = 0; i < LIMBS; i++) {
                long xi = x.getAtIndex(JAVA_LONG, i);
                for (int j = 0; j < LIMBS; j++) {
                    product.setAtIndex(JAVA_LONG, i + j,
                            product.getAtIndex(JAVA_LONG, i + j) + xi * y.getAtIndex(JAVA_LONG, j));
                }
            }
            for (int i = 0; i < 15; i++) {
                product.setAtIndex(JAVA_LONG, i, product.getAtIndex(JAVA_LONG, i)
                        + 38 * product.getAtIndex(JAVA_LONG, i + 16));
            }
            MemorySegment.copy(product, 0, o, 0, GF);
            carry(o);
            carry(o);
        }

        static void carry(MemorySegment o) {
            for (int i = 0; i < LIMBS; i++) {
                long v = o.getAtIndex(JAVA_LONG, i) + (1L << 16);
                long c = v >> 16;
                o.setAtIndex(JAVA_LONG, i, v - (c << 16));
                // The carry out of the top limb wraps round times 38: 2^256 = 38 mod p.
                int next = (i + 1) & 15;
                long add = i < 15 ? c - 1 : 38 * (c - 1);
                o.setAtIndex(JAVA_LONG, next, o.getAtIndex(JAVA_LONG, next) + add);
            }
        }

        /** 1/z by z^(p-2), the same squarings and multiplications for every z. */
        void invert(MemorySegment o, MemorySegment z) {
            MemorySegment x = gf();
            copy(x, z);
            for (int i = 253; i >= 0; i--) {
                mul(x, x, x);
                if (i != 2 && i != 4) {
                    mul(x, x, z);
                }
            }
            copy(o, x);
        }

        /** A field element as 32 little-endian bytes, fully reduced, in constant time. */
        void packField(MemorySegment out, long outOffset, MemorySegment n) {
            copy(packT, n);
            carry(packT);
            carry(packT);
            carry(packT);
            for (int round = 0; round < 2; round++) {
                packM.setAtIndex(JAVA_LONG, 0, packT.getAtIndex(JAVA_LONG, 0) - 0xffed);
                for (int i = 1; i < 15; i++) {
                    long previous = packM.getAtIndex(JAVA_LONG, i - 1);
                    packM.setAtIndex(JAVA_LONG, i,
                            packT.getAtIndex(JAVA_LONG, i) - 0xffff - ((previous >> 16) & 1));
                    packM.setAtIndex(JAVA_LONG, i - 1, previous & 0xffff);
                }
                long m14 = packM.getAtIndex(JAVA_LONG, 14);
                long m15 = packT.getAtIndex(JAVA_LONG, 15) - 0x7fff - ((m14 >> 16) & 1);
                packM.setAtIndex(JAVA_LONG, 15, m15);
                int borrow = (int) ((m15 >> 16) & 1);
                packM.setAtIndex(JAVA_LONG, 14, m14 & 0xffff);
                select(packT, packM, 1 - borrow);
            }
            for (int i = 0; i < LIMBS; i++) {
                long v = packT.getAtIndex(JAVA_LONG, i);
                out.set(JAVA_BYTE, outOffset + 2L * i, (byte) v);
                out.set(JAVA_BYTE, outOffset + 2L * i + 1, (byte) (v >> 8));
            }
        }

        /** A point's encoding: y, with the sign of x in the top bit. */
        void pack(MemorySegment out, MemorySegment[] p) {
            MemorySegment zi = gf();
            MemorySegment tx = gf();
            MemorySegment ty = gf();
            invert(zi, p[2]);
            mul(tx, p[0], zi);
            mul(ty, p[1], zi);
            packField(out, 0, ty);
            packField(packed, 0, tx);
            int sign = packed.get(JAVA_BYTE, 0) & 1;
            out.set(JAVA_BYTE, 31, (byte) (out.get(JAVA_BYTE, 31) ^ (sign << 7)));
        }

        @Override
        public void close() {
            try {
                for (MemorySegment segment : allocated) {
                    segment.fill((byte) 0);
                }
            } finally {
                arena.close();
            }
        }
    }
}
