package space.seclume.field;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.secret.SecretScope;

/**
 * A searchable fingerprint of an encrypted value that says less than the value
 * - stored next to it, in a numeric column, and searched with {@code =} or
 * {@code in}: a blind index.
 *
 * <p>A deterministic column gives equal plaintexts equal ciphertexts, which is
 * what makes it searchable - and what tells anyone with the table which rows
 * are equal. A blind index is HMAC-SHA-256 of the value, under a key derived
 * from the ring, <b>cut down to a few bits</b>: with {@code bits} bits and
 * {@code n} rows, every index value is shared by about {@code n / 2^bits} rows.
 * A search returns those candidates; the application decrypts them and keeps
 * the ones that match. Fewer bits, more candidates, less said about equality -
 * {@link #bitsFor} picks the number for a table size and a candidate count.
 *
 * <p>A {@link Transform} decides what is indexed: the whole value, the value
 * without regard to case, its digits, its first or last characters - so that
 * "the last four digits of the card", "names starting with Mü" or "e-mail,
 * whatever the case" can be searched without the value itself being searchable.
 * Every transform of every column has its own key; one index says nothing about
 * another.
 *
 * <p>During a rotation, {@link #searchTerms} gives one index value per key in
 * the ring, the primary's first; new rows are indexed under the primary key.
 */
public final class BlindIndex {

    /**
     * What of the value is indexed. Characters are Unicode code points of the
     * UTF-8 value; case folding is ASCII's, other letters are kept as they are.
     *
     * @param kind      {@code exact}, {@code digits}, {@code prefix} or {@code suffix}
     * @param length    for {@code prefix} and {@code suffix}, how many characters; 0 otherwise
     * @param foldCase  whether {@code A} and {@code a} are the same
     */
    public record Transform(String kind, int length, boolean foldCase) {

        /** The value as it is. */
        public static final Transform EXACT = new Transform("exact", 0, false);
        /** The value, whatever its (ASCII) case - an e-mail address. */
        public static final Transform CASE_INSENSITIVE = new Transform("exact", 0, true);
        /** Its digits only - a phone number however it was written. */
        public static final Transform DIGITS = new Transform("digits", 0, false);

        public Transform {
            if (!List.of("exact", "digits", "prefix", "suffix").contains(kind)) {
                throw new IllegalArgumentException("a transform is exact, digits, prefix or suffix, not " + kind);
            }
            boolean sized = kind.equals("prefix") || kind.equals("suffix");
            if (sized ? length < 1 || length > 64 : length != 0) {
                throw new IllegalArgumentException(kind + " takes " + (sized ? "1 to 64" : "no")
                        + " characters, not " + length);
            }
        }

        /** The first {@code n} characters - a value shorter than that is indexed whole. */
        public static Transform prefix(int n) {
            return new Transform("prefix", n, false);
        }

        /** The last {@code n} characters - the last four digits of a card. */
        public static Transform suffix(int n) {
            return new Transform("suffix", n, false);
        }

        /** The same, whatever the (ASCII) case. */
        public Transform caseInsensitive() {
            return new Transform(kind, length, true);
        }

        /** How the transform enters the key: {@code prefix3/ci}. */
        String code() {
            return kind + (length > 0 ? Integer.toString(length) : "") + (foldCase ? "/ci" : "");
        }
    }

    private final FieldKeys ring;
    private final String name;
    private final int bits;
    private final Transform transform;
    private final Map<Integer, SecretScope> keys;

    BlindIndex(FieldKeys ring, String name, int bits, Transform transform, Map<Integer, SecretScope> keys) {
        this.ring = ring;
        this.name = name;
        this.bits = bits;
        this.transform = transform;
        this.keys = keys;
    }

    /** The index's name, as given to {@link FieldKeys#blindIndex}. */
    public String name() {
        return name;
    }

    /** How many bits an index value has. */
    public int bits() {
        return bits;
    }

    /** What is indexed. */
    public Transform transform() {
        return transform;
    }

    /**
     * How many bits make at least about {@code candidates} rows share an index
     * value in a table of {@code rows}: {@code floor(log2(rows / candidates))},
     * at least 1 and at most 32 - rounded towards more candidates, which is
     * towards saying less.
     */
    public static int bitsFor(long rows, long candidates) {
        if (rows < 1 || candidates < 1) {
            throw new IllegalArgumentException("rows and candidates are at least 1");
        }
        long ratio = Math.max(1, rows / candidates);
        int bits = 63 - Long.numberOfLeadingZeros(ratio);
        return Math.max(1, Math.min(32, bits));
    }

    /** The index value of {@code plaintext} under the primary key, to store with the row. */
    public long term(MemorySegment plaintext) {
        return term(ring.primary(), plaintext);
    }

    /**
     * The index values to search for, one per key in the ring, the primary's
     * first, each once: {@code where index in (?, ?)}.
     */
    public List<Long> searchTerms(MemorySegment plaintext) {
        List<Long> terms = new ArrayList<>();
        terms.add(term(ring.primary(), plaintext));
        for (int keyId : ring.keyIds()) {
            if (keyId != ring.primary()) {
                long term = term(keyId, plaintext);
                if (!terms.contains(term)) {
                    terms.add(term);
                }
            }
        }
        return terms;
    }

    /** Sets parameter {@code index} to the value's index, or to SQL {@code NULL} for {@code null}. */
    public void set(PreparedStatement statement, int index, MemorySegment plaintext) throws SQLException {
        if (plaintext == null) {
            statement.setNull(index, Types.BIGINT);
        } else {
            statement.setLong(index, term(plaintext));
        }
    }

    long term(int keyId, MemorySegment plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("a NULL has no index; store NULL");
        }
        try (Arena arena = Arena.ofConfined();
             SecretScope transformed = SecretScope.in(arena, (int) Math.max(1, plaintext.byteSize()))) {
            int length = apply(transform, plaintext, transformed.segment());
            transformed.length(length);
            MemorySegment mac = arena.allocate(32);
            ring.lock().lock();
            try {
                ring.checkOpen();
                SecretScope key = keys.get(keyId);
                if (key == null) {
                    throw new FieldEncryptionException("the ring has no key " + keyId);
                }
                try (Hmac hmac = new Hmac(HashAlgorithm.SHA_256, key.secret())) {
                    hmac.update(transformed.segment(), 0, length);
                    hmac.doFinal(mac, 0);
                }
            } finally {
                ring.lock().unlock();
            }
            long value = mac.get(ValueLayout.JAVA_LONG_UNALIGNED.withOrder(java.nio.ByteOrder.BIG_ENDIAN), 0);
            mac.fill((byte) 0);
            return bits == 64 ? value : value >>> (64 - bits);
        }
    }

    /** Writes the transformed value into {@code out}; returns its length. */
    static int apply(Transform transform, MemorySegment in, MemorySegment out) {
        int length = (int) in.byteSize();
        int start = 0;
        int end = length;
        if (transform.kind().equals("prefix")) {
            end = Math.min(length, codePointEnd(in, length, transform.length()));
        } else if (transform.kind().equals("suffix")) {
            start = codePointStartFromEnd(in, length, transform.length());
        }
        int n = 0;
        for (int i = start; i < end; i++) {
            byte b = in.get(ValueLayout.JAVA_BYTE, i);
            if (transform.kind().equals("digits") && (b < '0' || b > '9')) {
                continue;
            }
            if (transform.foldCase() && b >= 'A' && b <= 'Z') {
                b = (byte) (b + ('a' - 'A'));
            }
            out.set(ValueLayout.JAVA_BYTE, n++, b);
        }
        return n;
    }

    /** The byte offset after the first {@code count} code points (or the length). */
    private static int codePointEnd(MemorySegment value, int length, int count) {
        int seen = 0;
        for (int i = 0; i < length; i++) {
            if (!continuation(value.get(ValueLayout.JAVA_BYTE, i))) {
                if (seen == count) {
                    return i;
                }
                seen++;
            }
        }
        return length;
    }

    /** The byte offset where the last {@code count} code points begin (or 0). */
    private static int codePointStartFromEnd(MemorySegment value, int length, int count) {
        int seen = 0;
        for (int i = length - 1; i >= 0; i--) {
            if (!continuation(value.get(ValueLayout.JAVA_BYTE, i))) {
                seen++;
                if (seen == count) {
                    return i;
                }
            }
        }
        return 0;
    }

    private static boolean continuation(byte b) {
        return (b & 0xc0) == 0x80;
    }

    void wipe() {
        keys.values().forEach(SecretScope::close);
    }

    @Override
    public String toString() {
        return "BlindIndex[" + name + ", " + transform.code() + ", " + bits + " bits]";
    }
}
