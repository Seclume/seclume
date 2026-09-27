package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Base64Off;

/**
 * OpenSSH's own private key format - {@code -----BEGIN OPENSSH PRIVATE
 * KEY-----}, what {@code ssh-keygen} writes by default - turned into what
 * OpenSSL reads, in native memory throughout.
 *
 * <p>OpenSSL does not read this format. The key inside is the same key, laid
 * out as SSH lays keys out, so it is taken apart here and written again:
 *
 * <ul>
 *   <li>{@code ssh-ed25519}: the 32-byte seed as PKCS#8;
 *   <li>{@code ecdsa-sha2-nistp256/384/521}: scalar, curve and point as SEC 1;
 *   <li>{@code ssh-rsa}: PKCS#1 - which also wants {@code d mod (p-1)} and
 *       {@code d mod (q-1)}, computed with {@link BigWords} rather than
 *       {@code BigInteger}, whose intermediate values would stay on the heap.
 * </ul>
 *
 * <p>Only unencrypted keys: one protected by a passphrase is refused, with the
 * way out - a secret provider keeps the key safe at rest, the passphrase would
 * only move the problem to another secret.
 */
public final class OpenSshPrivateKey {

    private static final String BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String END = "-----END OPENSSH PRIVATE KEY-----";
    private static final String MAGIC = "openssh-key-v1";

    private OpenSshPrivateKey() {
    }

    /** Whether {@code length} bytes of {@code key} are an OpenSSH private key file. */
    public static boolean is(MemorySegment key, int length) {
        return indexOf(key, 0, length, BEGIN) >= 0;
    }

    /** An upper bound for what {@link #toDer} writes. */
    public static int maxDerLength(int length) {
        return length + 256;
    }

    /**
     * Writes the key as DER - PKCS#8, SEC 1 or PKCS#1 - into {@code out}.
     *
     * @return how many bytes were written
     */
    public static int toDer(MemorySegment key, int length, MemorySegment out) {
        int begin = indexOf(key, 0, length, BEGIN);
        int end = indexOf(key, begin, length, END);
        if (begin < 0 || end < 0) {
            throw new IllegalArgumentException("not an OpenSSH private key file");
        }
        int from = begin + BEGIN.length();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment blob = arena.allocate(Base64Off.decodedUpperBound(end - from) + 16);
            try {
                int size = Base64Off.decode(key, from, end - from, blob, 0);
                return convert(new Reader(blob, size), out, arena);
            } finally {
                blob.fill((byte) 0);
            }
        }
    }

    private static int convert(Reader in, MemorySegment out, Arena arena) {
        for (int i = 0; i < MAGIC.length(); i++) {
            if (in.byteAt(i) != MAGIC.charAt(i)) {
                throw new IllegalArgumentException("not an OpenSSH key: the header is missing");
            }
        }
        in.at = MAGIC.length() + 1;
        String cipher = in.text();
        in.text();                                                  // kdf name
        in.skipString();                                            // kdf options
        if (!cipher.equals("none")) {
            throw new IllegalArgumentException("the OpenSSH key is protected by a passphrase ("
                    + cipher + "). Keep it unencrypted in a secret provider - which protects it "
                    + "at rest - or convert it: ssh-keygen -p -N '' -f key");
        }
        if (in.uint32() != 1) {
            throw new IllegalArgumentException("an OpenSSH key file with more than one key");
        }
        in.skipString();                                            // the public key
        int sectionLength = in.uint32();
        Reader section = new Reader(in.data.asSlice(in.at, sectionLength), sectionLength);
        if (section.raw32() != section.raw32()) {
            throw new IllegalArgumentException("the OpenSSH key's check values differ - a "
                    + "passphrase-protected key, or a damaged one");
        }
        String type = section.text();
        return switch (type) {
            case "ssh-ed25519" -> ed25519(section, out);
            case "ecdsa-sha2-nistp256" -> ecdsa(section, out, 32, new byte[] {
                    0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07});
            case "ecdsa-sha2-nistp384" -> ecdsa(section, out, 48, new byte[] {
                    0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x22});
            case "ecdsa-sha2-nistp521" -> ecdsa(section, out, 66, new byte[] {
                    0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x23});
            case "ssh-rsa" -> rsa(section, out, arena);
            default -> throw new IllegalArgumentException("an OpenSSH " + type + " key is not "
                    + "read here - Ed25519, ECDSA and RSA are");
        };
    }

    /** PKCS#8 for Ed25519: a fixed prefix and the 32-byte seed. */
    private static int ed25519(Reader in, MemorySegment out) {
        in.skipString();                                            // the public key
        int length = in.uint32();
        if (length != 64) {
            throw new IllegalArgumentException("an Ed25519 key of " + length + " bytes");
        }
        byte[] prefix = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x22, 0x04, 0x20};
        MemorySegment.copy(prefix, 0, out, ValueLayout.JAVA_BYTE, 0, prefix.length);
        MemorySegment.copy(in.data, in.at, out, prefix.length, 32); // the seed; the rest is the public key
        return prefix.length + 32;
    }

    /** SEC 1: {@code SEQUENCE { 1, OCTET STRING d, [0] curve, [1] BIT STRING Q }}. */
    private static int ecdsa(Reader in, MemorySegment out, int field, byte[] curve) {
        in.skipString();                                            // the curve's name
        int pointLength = in.uint32();
        int point = in.at;
        in.at += pointLength;
        int scalarLength = in.uint32();
        int scalar = in.at;
        while (scalarLength > field && in.data.get(ValueLayout.JAVA_BYTE, scalar) == 0) {
            scalar++;
            scalarLength--;
        }
        if (scalarLength > field) {
            throw new IllegalArgumentException("an ECDSA scalar longer than its curve");
        }
        int bitContent = pointLength + 1;
        int bitString = 1 + lengthSize(bitContent) + bitContent;
        int content = 3 + (2 + field) + (2 + curve.length) + (1 + lengthSize(bitString)
                + bitString);
        Writer w = new Writer(out);
        w.header(0x30, content);
        w.bytes(new byte[] {0x02, 0x01, 0x01});
        w.header(0x04, field);
        for (int i = scalarLength; i < field; i++) {
            w.put((byte) 0);
        }
        w.copy(in.data, scalar, scalarLength);
        w.header(0xa0, curve.length);
        w.bytes(curve);
        w.header(0xa1, bitString);
        w.header(0x03, bitContent);
        w.put((byte) 0);
        w.copy(in.data, point, pointLength);
        return w.at;
    }

    /** PKCS#1: {@code SEQUENCE { 0, n, e, d, p, q, d mod (p-1), d mod (q-1), q^-1 mod p }}. */
    private static int rsa(Reader in, MemorySegment out, Arena arena) {
        int[] n = in.mpint();
        int[] e = in.mpint();
        int[] d = in.mpint();
        int[] iqmp = in.mpint();
        int[] p = in.mpint();
        int[] q = in.mpint();
        MemorySegment dp = remainder(in.data, d, p, arena);
        MemorySegment dq = remainder(in.data, d, q, arena);
        try {
            int content = 3 + integerSize(in.data, n) + integerSize(in.data, e)
                    + integerSize(in.data, d) + integerSize(in.data, p) + integerSize(in.data, q)
                    + integerSize(dp, new int[] {0, (int) dp.byteSize()})
                    + integerSize(dq, new int[] {0, (int) dq.byteSize()})
                    + integerSize(in.data, iqmp);
            Writer w = new Writer(out);
            w.header(0x30, content);
            w.bytes(new byte[] {0x02, 0x01, 0x00});
            w.integer(in.data, n);
            w.integer(in.data, e);
            w.integer(in.data, d);
            w.integer(in.data, p);
            w.integer(in.data, q);
            w.integer(dp, new int[] {0, (int) dp.byteSize()});
            w.integer(dq, new int[] {0, (int) dq.byteSize()});
            w.integer(in.data, iqmp);
            return w.at;
        } finally {
            dp.fill((byte) 0);
            dq.fill((byte) 0);
        }
    }

    /** {@code d mod (prime - 1)} as big-endian bytes as long as the prime. */
    private static MemorySegment remainder(MemorySegment data, int[] d, int[] prime,
                                           Arena arena) {
        int words = BigWords.wordCount(prime[1]);
        int dWords = BigWords.wordCount(d[1]);
        MemorySegment modulus = arena.allocate(words * 4L);
        MemorySegment one = arena.allocate(words * 4L);
        MemorySegment x = arena.allocate(dWords * 4L);
        MemorySegment result = arena.allocate(words * 4L);
        MemorySegment bytes = arena.allocate(prime[1]);
        try {
            BigWords.fromBytes(data, prime[0], prime[1], modulus, words);
            BigWords.setSmall(one, words, 1);
            BigWords.subtract(modulus, one, words);
            BigWords.fromBytes(data, d[0], d[1], x, dWords);
            BigWords.mod(x, dWords, modulus, words, result, arena);
            BigWords.toBytes(result, words, bytes, 0, prime[1]);
            return bytes;
        } finally {
            modulus.fill((byte) 0);
            x.fill((byte) 0);
            result.fill((byte) 0);
        }
    }

    /** The DER INTEGER for big-endian bytes: leading zeroes gone, one added for a high bit. */
    private static int integerSize(MemorySegment data, int[] value) {
        int[] trimmed = trimmed(data, value);
        int length = trimmed[1] + (needsZero(data, trimmed) ? 1 : 0);
        return 1 + lengthSize(length) + length;
    }

    private static int[] trimmed(MemorySegment data, int[] value) {
        int from = value[0];
        int length = value[1];
        while (length > 1 && data.get(ValueLayout.JAVA_BYTE, from) == 0) {
            from++;
            length--;
        }
        return new int[] {from, length};
    }

    private static boolean needsZero(MemorySegment data, int[] value) {
        return value[1] == 0 || (data.get(ValueLayout.JAVA_BYTE, value[0]) & 0x80) != 0;
    }

    private static int lengthSize(int length) {
        return length < 0x80 ? 1 : length < 0x100 ? 2 : length < 0x10000 ? 3 : 4;
    }

    private static int indexOf(MemorySegment data, int from, int length, String text) {
        if (from < 0) {
            return -1;
        }
        outer:
        for (int i = from; i <= length - text.length(); i++) {
            for (int j = 0; j < text.length(); j++) {
                if (data.get(ValueLayout.JAVA_BYTE, i + j) != (byte) text.charAt(j)) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** SSH's wire types over native memory. */
    private static final class Reader {
        final MemorySegment data;
        final int length;
        int at;

        Reader(MemorySegment data, int length) {
            this.data = data;
            this.length = length;
        }

        int byteAt(int index) {
            return data.get(ValueLayout.JAVA_BYTE, index) & 0xff;
        }

        /** Four bytes as they are - the random check values. */
        int raw32() {
            if (at + 4 > length) {
                throw new IllegalArgumentException("the OpenSSH key ends too early");
            }
            int value = (byteAt(at) << 24) | (byteAt(at + 1) << 16) | (byteAt(at + 2) << 8)
                    | byteAt(at + 3);
            at += 4;
            return value;
        }

        /** A length or a count - checked against what is there. */
        int uint32() {
            int value = raw32();
            if (value < 0 || value > length) {
                throw new IllegalArgumentException("a length in the OpenSSH key is out of range");
            }
            return value;
        }

        void skipString() {
            int size = uint32();
            at += size;
        }

        /** A name - a cipher, a key type. Public. */
        String text() {
            int size = uint32();
            StringBuilder text = new StringBuilder(size);
            for (int i = 0; i < size; i++) {
                text.append((char) byteAt(at + i));
            }
            at += size;
            return text.toString();
        }

        /** Where an mpint's bytes are: {@code {offset, length}}. */
        int[] mpint() {
            int size = uint32();
            int[] where = {at, size};
            at += size;
            return where;
        }
    }

    /** DER into native memory - lengths included, they follow from the key. */
    private static final class Writer {
        final MemorySegment out;
        int at;

        Writer(MemorySegment out) {
            this.out = out;
        }

        void put(byte value) {
            out.set(ValueLayout.JAVA_BYTE, at++, value);
        }

        void bytes(byte[] values) {
            for (byte value : values) {
                put(value);
            }
        }

        void copy(MemorySegment from, int offset, int length) {
            MemorySegment.copy(from, offset, out, at, length);
            at += length;
        }

        void header(int tag, int length) {
            put((byte) tag);
            int size = lengthSize(length);
            if (size == 1) {
                put((byte) length);
                return;
            }
            put((byte) (0x80 | (size - 1)));
            for (int i = size - 2; i >= 0; i--) {
                put((byte) (length >>> (8 * i)));
            }
        }

        void integer(MemorySegment data, int[] value) {
            int[] trimmed = trimmed(data, value);
            boolean zero = needsZero(data, trimmed);
            header(0x02, trimmed[1] + (zero ? 1 : 0));
            if (zero) {
                put((byte) 0);
            }
            copy(data, trimmed[0], trimmed[1]);
        }
    }
}
