package space.seclume.tls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.AesGcm;
import space.seclume.crypto.AesGcmCipher;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hkdf;

/**
 * One direction of a TLS 1.3 record layer: key, IV, sequence number.
 *
 * <p>The cipher underneath is verified against the JDK's
 * ({@code AesGcmTest}); what lives here is the construction around it, and
 * every part of it is a place where two implementations can disagree while both
 * look correct on their own:
 *
 * <ul>
 *   <li>the <b>nonce</b> is the IV exclusive-ored with the sequence number,
 *       right-aligned - not the sequence number itself, and not concatenated;
 *   <li>the <b>additional data</b> is exactly the five bytes of the record
 *       header, including the length of what follows <i>with</i> its tag;
 *   <li>the <b>content type</b> travels <b>inside</b> the encryption, after the
 *       payload, and the outer type on the wire is always
 *       {@code application_data} - a record whose real type is visible is TLS
 *       1.2 thinking;
 *   <li>and padding is zero bytes after that inner type, so opening means
 *       walking backwards past the zeroes to find it.
 * </ul>
 *
 * <p><b>The sequence number is never sent.</b> Both sides count, and a record
 * that arrives out of order cannot be opened - which is the property that makes
 * a moved connection work at all: the sequence number is part of the state that
 * travels, and getting it wrong shows up immediately rather than subtly.
 *
 * <p>Keys and IV stay in native memory for their whole life. That is the reason
 * this class exists instead of an {@code SSLEngine}.
 */
public final class RecordProtection implements AutoCloseable {

    /** Every record on the wire claims to be this, whatever it really is. */
    public static final byte APPLICATION_DATA = 23;
    /** The header is type, two version bytes and two length bytes. */
    public static final int HEADER = 5;
    private static final int MAX_PLAINTEXT = 16384;
    /** RFC 8446 section 5.2: at most 2^14 + 256 bytes of ciphertext, the tag included. */
    private static final int MAX_INNER = MAX_PLAINTEXT + 256 - AesGcm.TAG;

    private final Arena arena = Arena.ofShared();
    private final AesGcmCipher key;
    private final MemorySegment iv;
    private final HashAlgorithm hash;
    private final MemorySegment secret;
    private final int keyLength;
    /** The nonce of the record in hand; rebuilt from IV and sequence number each time. */
    private final MemorySegment nonce;
    /**
     * The plaintext with its inner type, for sealing - and for opening into a
     * caller's buffer too small for the padding. Allocated on first use, since
     * a key is only ever used in one direction, and wiped after every record.
     */
    private MemorySegment content;
    private long sequence;

    private RecordProtection(HashAlgorithm hash, MemorySegment trafficSecret, int keyLength) {
        this.hash = hash;
        this.keyLength = keyLength;
        this.secret = arena.allocate(hash.digestLength());
        MemorySegment.copy(trafficSecret, 0, secret, 0, hash.digestLength());

        MemorySegment material = arena.allocate(keyLength);
        Hkdf.expandLabel(hash, secret, "key", null, material, 0, keyLength);
        this.key = AesGcmCipher.of(material, 0, keyLength);
        material.fill((byte) 0);

        this.iv = arena.allocate(AesGcm.NONCE);
        Hkdf.expandLabel(hash, secret, "iv", null, iv, 0, AesGcm.NONCE);
        this.nonce = arena.allocate(AesGcm.NONCE);
    }

    /**
     * Derives key and IV from a traffic secret.
     *
     * @param keyLength 16 for AES-128, 32 for AES-256
     */
    public static RecordProtection fromSecret(HashAlgorithm hash, MemorySegment trafficSecret,
            int keyLength) {
        return new RecordProtection(hash, trafficSecret, keyLength);
    }

    /** What a record turned out to be. */
    public record Opened(byte contentType, int length) {
    }

    /** How many bytes a record of this payload will take on the wire. */
    public static int sealedLength(int plaintextLength) {
        return HEADER + plaintextLength + 1 + AesGcm.TAG;
    }

    /**
     * Writes one complete record - header and all.
     *
     * @return the number of bytes written
     */
    public int seal(byte contentType, MemorySegment plain, long offset, int length,
            MemorySegment out, long outOffset) {
        if (length > MAX_PLAINTEXT) {
            throw new IllegalArgumentException("a record holds at most " + MAX_PLAINTEXT
                    + " bytes, not " + length);
        }
        int inner = length + 1;
        int body = inner + AesGcm.TAG;
        writeHeader(out, outOffset, body);

        // One nonce and one content buffer for the life of the key, not an
        // arena per record: allocating, zeroing and freeing 16 KiB each time
        // cost more than the AES-GCM of a short record (RecordBenchmark).
        nonce();
        MemorySegment content = content();
        if (length > 0) {
            MemorySegment.copy(plain, offset, content, 0, length);
        }
        content.set(ValueLayout.JAVA_BYTE, length, contentType);
        try {
            key.encrypt(nonce, 0, out, outOffset, HEADER, content, 0, inner,
                    out, outOffset + HEADER);
        } finally {
            content.asSlice(0, inner).fill((byte) 0);
        }
        sequence++;
        return HEADER + body;
    }

    /**
     * Opens one complete record, header included.
     *
     * @return what it was, or null if the tag did not match
     */
    public Opened open(MemorySegment record, long offset, int recordLength,
            MemorySegment out, long outOffset) {
        int body = recordLength - HEADER;
        if (body <= AesGcm.TAG) {
            return null;                    // not even room for the inner type
        }
        int inner = body - AesGcm.TAG;
        if (inner > MAX_INNER) {
            throw new IllegalArgumentException("a record holds at most " + MAX_INNER
                    + " bytes of content and padding, not " + inner);
        }
        // Straight into the caller's buffer when the inner type and padding fit
        // there too - RecordStream's always does - and through the content
        // buffer otherwise, so that exactly the payload lands in out.
        boolean direct = out.byteSize() - outOffset >= inner;
        MemorySegment target = direct ? out : content();
        long base = direct ? outOffset : 0;
        nonce();
        boolean ok = key.decrypt(nonce, 0, record, offset, HEADER,
                record, offset + HEADER, inner, target, base);
        if (!ok) {
            return null;
        }
        sequence++;
        // Backwards past the padding: the last byte that is not zero is the
        // real content type. A record that is all zeroes has none and is a
        // protocol error rather than an empty message.
        int at = inner - 1;
        while (at >= 0 && target.get(ValueLayout.JAVA_BYTE, base + at) == 0) {
            at--;
        }
        if (at < 0) {
            target.asSlice(base, inner).fill((byte) 0);
            return null;
        }
        byte contentType = target.get(ValueLayout.JAVA_BYTE, base + at);
        if (direct) {
            // Only the type is left to clear behind the payload; the padding
            // after it is zeroes already.
            target.set(ValueLayout.JAVA_BYTE, base + at, (byte) 0);
        } else {
            if (at > 0) {
                MemorySegment.copy(target, 0, out, outOffset, at);
            }
            target.asSlice(0, inner).fill((byte) 0);
        }
        return new Opened(contentType, at);
    }

    /**
     * Advances to the next generation of keys after a KeyUpdate.
     *
     * <p>The new secret comes from the old one, the sequence number goes back
     * to zero, and the old key is gone. Forgetting to reset the counter is the
     * classic way to make a key update look like it worked until the first
     * record after it.
     */
    public RecordProtection next() {
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment updated = scratch.allocate(hash.digestLength());
            Hkdf.expandLabel(hash, secret, "traffic upd", null, updated, 0, hash.digestLength());
            return new RecordProtection(hash, updated, keyLength);
        }
    }

    /** The number of records processed in this direction so far. */
    public long sequence() {
        return sequence;
    }

    // ---- what writing a connection down needs, and nothing more -----------
    //
    // These three are package-private on purpose. Handing out a traffic
    // secret is the one operation that can undo everything this class is for,
    // so the only callers able to reach it are the ones in this package that
    // write a connection down - see TlsMigration, which copies it straight
    // into native memory the caller has to wipe. There is no public getter and
    // there should not be one.

    HashAlgorithm hash() {
        return hash;
    }

    int keyLength() {
        return keyLength;
    }

    /** Copies the current traffic secret out - {@code hash().digestLength()} bytes. */
    void copySecretInto(MemorySegment out, long offset) {
        MemorySegment.copy(secret, 0, out, offset, hash.digestLength());
    }

    /** Which AES-GCM this protection runs on: {@code openssl}, {@code cng} or {@code java}. */
    public String cipherImplementation() {
        return key.implementation();
    }

    /** Sets it - for a connection rebuilt from a written-down state. */
    public void sequence(long value) {
        this.sequence = value;
    }

    private void writeHeader(MemorySegment out, long offset, int bodyLength) {
        out.set(ValueLayout.JAVA_BYTE, offset, APPLICATION_DATA);
        out.set(ValueLayout.JAVA_BYTE, offset + 1, (byte) 0x03);
        out.set(ValueLayout.JAVA_BYTE, offset + 2, (byte) 0x03);
        out.set(ValueLayout.JAVA_BYTE, offset + 3, (byte) (bodyLength >>> 8));
        out.set(ValueLayout.JAVA_BYTE, offset + 4, (byte) bodyLength);
    }

    /** IV xor sequence number, the number right-aligned in the twelve bytes. */
    private void nonce() {
        MemorySegment.copy(iv, 0, nonce, 0, AesGcm.NONCE);
        for (int i = 0; i < 8; i++) {
            int at = AesGcm.NONCE - 1 - i;
            byte counter = (byte) (sequence >>> (8 * i));
            nonce.set(ValueLayout.JAVA_BYTE, at,
                    (byte) (nonce.get(ValueLayout.JAVA_BYTE, at) ^ counter));
        }
    }

    private MemorySegment content() {
        if (content == null) {
            content = arena.allocate(MAX_INNER);
        }
        return content;
    }

    @Override
    public void close() {
        key.close();
        arena.close();
    }
}
