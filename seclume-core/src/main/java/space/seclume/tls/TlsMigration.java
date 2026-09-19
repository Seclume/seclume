package space.seclume.tls;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.zip.CRC32;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.secret.SecretScope;

/**
 * The encryption half of a connection, written down so that another process
 * or another machine can carry it on.
 *
 * <p>This is the piece an {@code SSLEngine} cannot give you, and the reason
 * this package exists: no method of {@code SSLSession} or {@code SSLEngine}
 * is named for a traffic secret or a record sequence number, by design. Here
 * they are both, in a fixed format - shaped after {@code tcp/Migration}, for
 * the same reasons: fixed widths, big endian, a version that refuses rather
 * than half-understands, a length and a checksum.
 *
 * <p><b>What travels, and why exactly this.</b> A traffic secret and a
 * sequence number per direction, plus the cipher suite needed to use them.
 * Not the key and IV: those are one {@code HKDF-Expand-Label} away from the
 * secret, and deriving them again on the far side is cheaper than moving
 * them and keeps one representation of the truth. The <b>sequence numbers
 * are the subtle part</b> - a connection resumed with them reset to zero
 * looks entirely healthy until the first record, which the peer then refuses
 * with {@code bad_record_mac} and no further explanation.
 *
 * <p><b>This blob is key material.</b> {@code tcp/Migration} says its
 * carrier must be authenticated, because sequence numbers let somebody
 * inject into a session. This one is stronger: whoever reads these bytes can
 * decrypt and forge everything on the connection, in both directions. The
 * carrier must therefore be <b>confidential as well as authenticated</b>,
 * and the buffer it is written into should be one that gets wiped - a
 * {@link SecretScope}, not an ordinary array. Nothing here can enforce that,
 * so it is stated plainly instead.
 */
final class TlsMigration {

    /** {@code ZLTS} - so that a wrong buffer is refused instead of parsed. */
    static final int MAGIC = 0x5a4c5453;
    /** Bump whenever a field moves, and never reuse a number. */
    static final int VERSION = 1;

    private static final int HEADER = 16;        // magic, version, length, checksum
    private static final int BODY = 24;          // suite, key length, two sequence numbers
    private static final int CHECKSUM_AT = 12;

    private static final int SHA_256_ID = 1;
    private static final int SHA_384_ID = 2;

    private TlsMigration() {
    }

    /** How many bytes {@link #encode} writes for a connection using this hash. */
    static int encodedLength(HashAlgorithm hash) {
        return HEADER + BODY + 2 * hash.digestLength();
    }

    /**
     * Writes the two directions out.
     *
     * @return the number of bytes written
     */
    static int encode(MemorySegment out, long offset, RecordProtection reading,
            RecordProtection writing) {
        HashAlgorithm hash = reading.hash();
        if (writing.hash() != hash || writing.keyLength() != reading.keyLength()) {
            throw new IllegalStateException("the two directions disagree about the cipher "
                    + "suite, which cannot happen in TLS 1.3 and means something is confused");
        }
        int length = encodedLength(hash);
        int at = 0;
        putInt(out, offset + at, MAGIC);
        at += 4;
        putInt(out, offset + at, VERSION);
        at += 4;
        putInt(out, offset + at, length);
        at += 4;
        putInt(out, offset + at, 0);                 // the checksum, filled in last
        at += 4;

        putInt(out, offset + at, hashId(hash));
        at += 4;
        putInt(out, offset + at, reading.keyLength());
        at += 4;
        putLong(out, offset + at, reading.sequence());
        at += 8;
        putLong(out, offset + at, writing.sequence());
        at += 8;

        reading.copySecretInto(out, offset + at);
        at += hash.digestLength();
        writing.copySecretInto(out, offset + at);

        putInt(out, offset + CHECKSUM_AT, checksum(out, offset, length));
        return length;
    }

    /** The two directions rebuilt; whoever asked for them closes them. */
    record Thawed(RecordProtection reading, RecordProtection writing) {
    }

    /**
     * Reads a frozen connection back.
     *
     * <p>Every refusal says what was wrong. The alternative - a half-built
     * pair of keys - turns a transfer problem into a protocol mystery one
     * round trip later, which is exactly the kind of fault this format is
     * shaped to avoid.
     */
    static Thawed decode(MemorySegment in, long offset, int available) {
        if (available < HEADER + BODY) {
            throw new IllegalArgumentException("a frozen TLS connection is at least "
                    + (HEADER + BODY) + " bytes, got " + available);
        }
        int magic = getInt(in, offset);
        if (magic != MAGIC) {
            throw new IllegalArgumentException("not a frozen TLS connection: magic is 0x"
                    + Integer.toHexString(magic) + ", expected 0x" + Integer.toHexString(MAGIC));
        }
        int version = getInt(in, offset + 4);
        if (version != VERSION) {
            throw new IllegalArgumentException("this is a version " + version
                    + " frozen connection and this node speaks version " + VERSION
                    + " - it must be closed rather than half understood");
        }
        int length = getInt(in, offset + 8);
        if (length < HEADER + BODY || length > available) {
            throw new IllegalArgumentException("the frozen connection claims " + length
                    + " bytes and " + available + " are here");
        }
        if (checksum(in, offset, length) != getInt(in, offset + CHECKSUM_AT)) {
            throw new IllegalArgumentException("the frozen connection is damaged - its checksum "
                    + "does not match, so its keys cannot be trusted");
        }

        int at = HEADER;
        HashAlgorithm hash = hashFor(getInt(in, offset + at));
        at += 4;
        int keyLength = getInt(in, offset + at);
        at += 4;
        if (keyLength != 16 && keyLength != 32) {
            throw new IllegalArgumentException("a key length of " + keyLength
                    + " bytes belongs to no TLS 1.3 cipher suite");
        }
        long readSequence = getLong(in, offset + at);
        at += 8;
        long writeSequence = getLong(in, offset + at);
        at += 8;
        if (length != encodedLength(hash)) {
            throw new IllegalArgumentException("the frozen connection is " + length
                    + " bytes, and a " + hash + " connection is " + encodedLength(hash));
        }

        int digest = hash.digestLength();
        // The secrets are copied into memory that gets wiped, used to derive
        // key and IV, and wiped again - they exist in this method and nowhere
        // else on the way in.
        try (SecretScope secrets = SecretScope.allocate(2 * digest)) {
            MemorySegment.copy(in, offset + at, secrets.segment(), 0, 2L * digest);
            RecordProtection reading = RecordProtection.fromSecret(
                    hash, secrets.segment().asSlice(0, digest), keyLength);
            RecordProtection writing = null;
            try {
                writing = RecordProtection.fromSecret(
                        hash, secrets.segment().asSlice(digest, digest), keyLength);
            } finally {
                if (writing == null) {
                    reading.close();
                }
            }
            reading.sequence(readSequence);
            writing.sequence(writeSequence);
            return new Thawed(reading, writing);
        }
    }

    private static int hashId(HashAlgorithm hash) {
        return switch (hash) {
            case SHA_256 -> SHA_256_ID;
            case SHA_384 -> SHA_384_ID;
            default -> throw new IllegalStateException("no TLS 1.3 cipher suite uses " + hash);
        };
    }

    private static HashAlgorithm hashFor(int id) {
        return switch (id) {
            case SHA_256_ID -> HashAlgorithm.SHA_256;
            case SHA_384_ID -> HashAlgorithm.SHA_384;
            default -> throw new IllegalArgumentException("unknown cipher suite hash " + id);
        };
    }

    /**
     * Corruption, not tampering - see the class note. The checksum is
     * computed with its own field zeroed, so that it does not depend on
     * whatever happened to be there.
     */
    private static int checksum(MemorySegment data, long offset, int length) {
        int saved = getInt(data, offset + CHECKSUM_AT);
        putInt(data, offset + CHECKSUM_AT, 0);
        try {
            CRC32 crc = new CRC32();
            crc.update(data.asSlice(offset, length).asByteBuffer());
            return (int) crc.getValue();
        } finally {
            putInt(data, offset + CHECKSUM_AT, saved);
        }
    }

    private static void putInt(MemorySegment out, long at, int value) {
        out.set(ValueLayout.JAVA_BYTE, at, (byte) (value >>> 24));
        out.set(ValueLayout.JAVA_BYTE, at + 1, (byte) (value >>> 16));
        out.set(ValueLayout.JAVA_BYTE, at + 2, (byte) (value >>> 8));
        out.set(ValueLayout.JAVA_BYTE, at + 3, (byte) value);
    }

    private static void putLong(MemorySegment out, long at, long value) {
        putInt(out, at, (int) (value >>> 32));
        putInt(out, at + 4, (int) value);
    }

    private static int getInt(MemorySegment in, long at) {
        return ((in.get(ValueLayout.JAVA_BYTE, at) & 0xff) << 24)
                | ((in.get(ValueLayout.JAVA_BYTE, at + 1) & 0xff) << 16)
                | ((in.get(ValueLayout.JAVA_BYTE, at + 2) & 0xff) << 8)
                | (in.get(ValueLayout.JAVA_BYTE, at + 3) & 0xff);
    }

    private static long getLong(MemorySegment in, long at) {
        return ((long) getInt(in, at) << 32) | (getInt(in, at + 4) & 0xffffffffL);
    }
}
