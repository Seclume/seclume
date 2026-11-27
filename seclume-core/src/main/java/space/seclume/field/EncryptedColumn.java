package space.seclume.field;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import space.seclume.crypto.AesGcmSiv;
import space.seclume.internal.Entropy;
import space.seclume.secret.SecretScope;

/**
 * One encrypted column: values are encrypted in the application, before they
 * are bound, and decrypted after they are read. The database, its backups, its
 * replicas, its logs and whoever administers them see only ciphertext.
 *
 * <p>The ciphertext is an ordinary binary value - {@code bytea},
 * {@code varbinary}, {@code BLOB} or {@code RAW} - bound with
 * {@code setBytes} and read with {@code getBytes}. So it works on every JDBC
 * driver, seclume's or not, and the format is the same on all of them: a
 * value written through PostgreSQL decrypts after a migration to SQL Server.
 *
 * <pre>
 * EncryptedColumn token = keys.column("tenant.api_token", Mode.RANDOMIZED);
 * try (SecretScope value = SecretScope.fromProvider(issued);
 *      PreparedStatement update = connection.prepareStatement(
 *              "update tenant set api_token = ? where id = ?")) {
 *     token.set(update, 1, value.secret());
 *     update.setLong(2, tenantId);
 *     update.executeUpdate();
 * }
 * ...
 * try (SecretScope value = SecretScope.allocate(256);
 *      ResultSet rows = query.executeQuery()) {
 *     rows.next();
 *     value.length(token.readInto(rows, 1, value.segment()));
 * }
 * </pre>
 *
 * <h2>What stays off the heap</h2>
 *
 * <p>The data key and the column key are in locked native memory. A value
 * bound with {@link #set(PreparedStatement, int, MemorySegment)} and read with
 * {@link #readInto} is plaintext in native memory only; the ciphertext on the
 * heap is not a secret. {@link #setString} and {@link #getString} are for data
 * that is confidential but lives as a {@code String} in the application anyway
 * - a name, a date of birth: they keep it from the database, not from the heap.
 *
 * <h2>Randomized and deterministic</h2>
 *
 * <p>{@link Mode#RANDOMIZED} draws a fresh nonce for every value: the same
 * plaintext gives a different ciphertext every time, and the database learns
 * nothing but the length. {@link Mode#DETERMINISTIC} gives the same plaintext
 * the same ciphertext under the same key, so {@code where ssn = ?}, a unique
 * index and a join on the column still work. The price is that the database
 * sees which rows hold equal values - and with few possible values (a
 * gender, a blood group) that can be all it needs. Choose it per column, for
 * columns that are searched and have many distinct values.
 *
 * <p>Both are AES-256-GCM-SIV (RFC 8452), randomized with a random nonce and
 * deterministic with a fixed one - which GCM-SIV is designed to survive: a
 * repeated nonce reveals only that two messages are equal. A tag of sixteen
 * bytes authenticates every value, so a ciphertext that was altered, or taken
 * from another column, does not decrypt.
 *
 * <h2>The format, version 1</h2>
 *
 * <pre>
 *   [ 1 version = 1 ][ 1 flags ][ 4 key number, big endian ][ 12 nonce ][ 32 commitment ][ ciphertext ][ 16 tag ]
 * </pre>
 *
 * <p>Flags: bit 0 is set for deterministic; no other bit is defined, and a
 * value with another set is refused. The first six bytes are the associated
 * data, followed by the caller's {@code context} if there is one. The
 * commitment is HMAC-SHA-256 of the first eighteen bytes under the column's
 * commitment key: AES-GCM-SIV alone does not bind a ciphertext to one key, and
 * with this a value cannot be made to open under two keys of a ring. Sixty-six
 * bytes of overhead, whatever the value.
 *
 * <h2>Context</h2>
 *
 * <p>A context - a row's primary key, a tenant's id - is authenticated with
 * the value but not stored with it. A ciphertext copied into another row then
 * fails to decrypt there instead of quietly turning up. Deterministic values
 * with a context are equal only within the same context, so a column searched
 * across rows takes none.
 *
 * <h2>What it does not hide</h2>
 *
 * <p>The length of each value (to the byte), whether it is NULL - SQL NULL is
 * stored as NULL - and, for deterministic columns, which values are equal.
 * Ordering and range queries on an encrypted column are not possible.
 */
public final class EncryptedColumn {

    /** How equal plaintexts are encrypted. */
    public enum Mode {
        /** A fresh nonce for every value: equal plaintexts are not recognisable. */
        RANDOMIZED((byte) 0),
        /** A fixed nonce: equal plaintexts give equal ciphertexts, so the column can be searched. */
        DETERMINISTIC((byte) 1);

        private final byte flag;

        Mode(byte flag) {
            this.flag = flag;
        }

        byte flag() {
            return flag;
        }
    }

    /**
     * Whether a value must be bound to a context - the row's key, the
     * tenant, the record's id - before it is written or read.
     */
    public enum Context {
        /** A context may be given; without one a value opens in any row of the column. */
        OPTIONAL,
        /**
         * Every value is bound to a context: one written or read without a
         * context - which would open in any other row - is refused. The
         * format is the same; only the column's use is checked.
         */
        REQUIRED
    }

    /**
     * How a value's length is hidden. Without padding the ciphertext is the
     * plaintext's length plus {@link #OVERHEAD}, to the byte: a column of
     * diagnoses or salaries tells by its lengths alone more than it should.
     * With padding the value is written as its length (four bytes), itself and
     * zeros up to the next size the padding allows - only that size shows.
     * The flag that says so is part of the authenticated header, and every
     * column reads padded and unpadded values alike: switching padding on
     * needs no migration, {@link #needsReencryption} finds what to rewrite.
     */
    public static final class Padding {

        /** No padding: the length shows to the byte. */
        public static final Padding NONE = new Padding(0, false);

        private final int size;
        private final boolean powerOfTwo;

        private Padding(int size, boolean powerOfTwo) {
            this.size = size;
            this.powerOfTwo = powerOfTwo;
        }

        /**
         * Every value padded to a multiple of {@code bytes} (2 to 65536): with
         * 32, a value of 1 to 28 bytes looks like every other of them.
         */
        public static Padding toMultipleOf(int bytes) {
            if (bytes < 2 || bytes > 65536) {
                throw new IllegalArgumentException("padding to multiples of 2 to 65536 bytes, not "
                        + bytes);
            }
            return new Padding(bytes, false);
        }

        /**
         * Every value padded to the next power of two, at least
         * {@code minimum} (2 to 65536): what shows is the order of magnitude,
         * at a cost of less than double.
         */
        public static Padding toPowerOfTwo(int minimum) {
            if (minimum < 2 || minimum > 65536) {
                throw new IllegalArgumentException("padding to powers of two of at least 2 to "
                        + "65536 bytes, not " + minimum);
            }
            return new Padding(minimum, true);
        }

        boolean pads() {
            return size > 0;
        }

        /** What {@code content} bytes - the length prefix and the value - are padded to. */
        long paddedLength(long content) {
            if (powerOfTwo) {
                long padded = size;
                while (padded < content) {
                    padded <<= 1;
                }
                return padded;
            }
            return (content + size - 1) / size * size;
        }

        /** Part of the column's identity in its ring's cache. */
        String code() {
            return size == 0 ? "none" : (powerOfTwo ? "pow2:" : "mul:") + size;
        }

        @Override
        public String toString() {
            return size == 0 ? "no padding" : powerOfTwo ? "padded to powers of two from " + size
                    : "padded to multiples of " + size;
        }
    }

    /** The flag bit that says a value is padded - see {@link Padding}. */
    static final byte PADDED = 0x02;
    /** The length prefix of a padded value. */
    static final int LENGTH_PREFIX = 4;

    /** The version byte of this format. */
    public static final byte VERSION = 1;
    /** Version, flags and key number: the associated data every value starts with. */
    static final int HEADER = 6;
    /** HMAC-SHA-256 of the header and the nonce under the column's commitment key. */
    static final int COMMITMENT = 32;
    /** Where the ciphertext starts. */
    static final int BODY = HEADER + AesGcmSiv.NONCE + COMMITMENT;
    /** What a value costs beyond its plaintext. */
    public static final int OVERHEAD = BODY + AesGcmSiv.TAG;

    private static final ValueLayout.OfInt BE_INT =
            ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);
    private static final byte[] NO_CONTEXT = new byte[0];

    private final FieldKeys ring;
    private final String name;
    private final Mode mode;
    private final Context context;
    private final Padding padding;
    /** Replaced when the ring reads its keys again after a checkpoint; see {@link FieldKeys}. */
    private volatile Map<Integer, SecretScope> keys;

    EncryptedColumn(FieldKeys ring, String name, Mode mode, Context context, Padding padding,
                    Map<Integer, SecretScope> keys) {
        this.ring = ring;
        this.name = name;
        this.mode = mode;
        this.context = context;
        this.padding = padding;
        this.keys = keys;
    }

    /** How this column hides the length of what it writes. */
    public Padding padding() {
        return padding;
    }

    public String name() {
        return name;
    }

    public Mode mode() {
        return mode;
    }

    /** Whether every value of this column has to be bound to a context. */
    public Context context() {
        return context;
    }

    private byte[] bound(byte[] given) {
        byte[] chosen = given == null ? NO_CONTEXT : given;
        if (chosen.length == 0 && context == Context.REQUIRED) {
            throw new IllegalArgumentException("the column " + name + " binds every value to a "
                    + "context, and none was given - without one, a value opens in any row");
        }
        return chosen;
    }

    // ------------------------------------------------------------------- core

    /** Encrypts under the primary key. */
    public byte[] encrypt(MemorySegment plaintext) {
        return encrypt(plaintext, NO_CONTEXT);
    }

    /**
     * Encrypts under the primary key, bound to {@code context}.
     *
     * @param context authenticated, not stored; the same has to be given to decrypt
     */
    public byte[] encrypt(MemorySegment plaintext, byte[] context) {
        return encrypt(ring.primary(), plaintext, context);
    }

    private byte[] encrypt(int keyId, MemorySegment plaintext, byte[] context) {
        if (plaintext == null) {
            throw new IllegalArgumentException("a NULL is stored as NULL, not encrypted");
        }
        long length = plaintext.byteSize();
        if (length > Integer.MAX_VALUE - OVERHEAD - 8) {
            throw new IllegalArgumentException("a field value is at most about 2 GB");
        }
        byte[] context0 = bound(context);
        if (padding.pads()) {
            long padded = padding.paddedLength(LENGTH_PREFIX + length);
            if (padded > Integer.MAX_VALUE - OVERHEAD - 8) {
                throw new IllegalArgumentException("a field value is at most about 2 GB, padded");
            }
            // The value with its length in front and zeros behind, in a
            // SecretScope: it is the plaintext as much as the value itself.
            try (SecretScope body = SecretScope.allocate((int) padded)) {
                MemorySegment content = body.segment();
                content.set(BE_INT, 0, (int) length);
                MemorySegment.copy(plaintext, 0, content, LENGTH_PREFIX, length);
                return seal(keyId, content, padded, (byte) (mode.flag() | PADDED), context0);
            }
        }
        return seal(keyId, plaintext, length, mode.flag(), context0);
    }

    private byte[] seal(int keyId, MemorySegment plaintext, long length, byte flags,
                        byte[] context0) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment value = arena.allocate(OVERHEAD + length);
            value.set(ValueLayout.JAVA_BYTE, 0, VERSION);
            value.set(ValueLayout.JAVA_BYTE, 1, flags);
            value.set(BE_INT, 2, keyId);
            if (mode == Mode.RANDOMIZED) {
                Entropy.fill(value, HEADER, AesGcmSiv.NONCE);
            }
            MemorySegment aad = associatedData(arena, value, context0);
            ring.underKeys(() -> {
                MemorySegment keys = columnKey(keyId);
                commitment(keys, value, value, HEADER + AesGcmSiv.NONCE);
                AesGcmSiv.encrypt(keys, 0, FieldKeys.KEY_LENGTH,
                        value, HEADER, aad, 0, aad.byteSize(),
                        plaintext, 0, length, value, BODY);
                return null;
            });
            return value.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /**
     * How many bytes {@code ciphertext} decrypts to - at most, for a padded
     * value, whose length only the decryption reveals; checks only the format.
     * Size a buffer with it, and take the length {@code decrypt} returns.
     */
    public int plaintextLength(byte[] ciphertext) {
        header(ciphertext);
        return ciphertext.length - OVERHEAD - (padded(ciphertext) ? LENGTH_PREFIX : 0);
    }

    private static boolean padded(byte[] ciphertext) {
        return (ciphertext[1] & PADDED) != 0;
    }

    /** Which key {@code ciphertext} was encrypted under. */
    public int keyId(byte[] ciphertext) {
        return header(ciphertext);
    }

    /** Decrypts into native memory the caller owns. */
    public int decrypt(byte[] ciphertext, MemorySegment target) {
        return decrypt(ciphertext, NO_CONTEXT, target);
    }

    /**
     * Decrypts into native memory the caller owns - usually a
     * {@link SecretScope}'s {@code segment()}.
     *
     * @return the length of the plaintext
     * @throws FieldEncryptionException if the value is not this column's, under
     *         a key the ring does not hold, or does not authenticate; then
     *         nothing is left in {@code target}
     */
    public int decrypt(byte[] ciphertext, byte[] context, MemorySegment target) {
        int keyId = header(ciphertext);
        int length = ciphertext.length - OVERHEAD;
        if (padded(ciphertext)) {
            if (length < LENGTH_PREFIX) {
                throw new FieldEncryptionException("a padded value of " + name + " is shorter "
                        + "than its length prefix");
            }
            try (SecretScope body = SecretScope.allocate(Math.max(1, length))) {
                open(ciphertext, keyId, length, context, body.segment());
                int inside = body.segment().get(BE_INT, 0);
                if (inside < 0 || inside > length - LENGTH_PREFIX) {
                    // Authenticated, so written so: a value made by something
                    // that is not this format, under this column's key.
                    throw new FieldEncryptionException("a padded value of " + name + " says it "
                            + "is " + inside + " bytes long, which does not fit its padding");
                }
                if (target.byteSize() < inside) {
                    throw new FieldEncryptionException("the value of " + name + " is " + inside
                            + " bytes and does not fit into " + target.byteSize());
                }
                MemorySegment.copy(body.segment(), LENGTH_PREFIX, target, 0, inside);
                return inside;
            }
        }
        if (target.byteSize() < length) {
            throw new FieldEncryptionException("the value of " + name + " is " + length
                    + " bytes and does not fit into " + target.byteSize());
        }
        open(ciphertext, keyId, length, context, target);
        return length;
    }

    /** Authenticates {@code ciphertext} and decrypts its {@code length} bytes into {@code target}. */
    private void open(byte[] ciphertext, int keyId, int length, byte[] context,
                      MemorySegment target) {
        if (target.byteSize() < length) {
            throw new FieldEncryptionException("the value of " + name + " is " + length
                    + " bytes and does not fit into " + target.byteSize());
        }
        byte[] context0 = bound(context);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment value = arena.allocate(ciphertext.length);
            MemorySegment.copy(ciphertext, 0, value, ValueLayout.JAVA_BYTE, 0, ciphertext.length);
            MemorySegment aad = associatedData(arena, value, context0);
            boolean authentic = ring.underKeys(() -> {
                MemorySegment keys = columnKey(keyId);
                // The commitment first: a value made under another key - one that
                // happens to open under this one too - is refused before AES-GCM-SIV
                // is asked, and with the same words, so that neither check is an oracle.
                MemorySegment expected = arena.allocate(COMMITMENT);
                commitment(keys, value, expected, 0);
                return space.seclume.crypto.ConstantTime.equals(expected, 0, value,
                        HEADER + AesGcmSiv.NONCE, COMMITMENT)
                        && AesGcmSiv.decrypt(keys, 0, FieldKeys.KEY_LENGTH,
                                value, HEADER, aad, 0, aad.byteSize(),
                                value, BODY, length, target, 0);
            });
            if (!authentic) {
                throw new FieldEncryptionException("a value of " + name + " did not authenticate"
                        + " - another column's, another row's context, or altered");
            }
        }
    }

    /**
     * Every ciphertext {@code plaintext} has in this deterministic column: one
     * per key of the ring, the primary first. While a rotation is under way,
     * {@code where ssn in (?, ?)} with these finds the row whichever key it is
     * still under.
     */
    public List<byte[]> searchTerms(MemorySegment plaintext) {
        if (mode != Mode.DETERMINISTIC) {
            throw new IllegalStateException(name + " is randomized: its values cannot be "
                    + "searched for, only read");
        }
        List<byte[]> terms = new ArrayList<>();
        terms.add(encrypt(ring.primary(), plaintext, NO_CONTEXT));
        for (int keyId : ring.keyIds()) {
            if (keyId != ring.primary()) {
                terms.add(encrypt(keyId, plaintext, NO_CONTEXT));
            }
        }
        return terms;
    }

    /** True when {@code ciphertext} is under another key than the primary. */
    public boolean needsReencryption(byte[] ciphertext) {
        // Under an older key - or unpadded in a column that pads now, whose
        // length still shows. (Padded in a column without padding stays: taking
        // it off would show the length it hides.)
        return header(ciphertext) != ring.primary() || (padding.pads() && !padded(ciphertext));
    }

    /** {@link #reencrypt(byte[], byte[])} without a context. */
    public byte[] reencrypt(byte[] ciphertext) {
        return reencrypt(ciphertext, NO_CONTEXT);
    }

    /**
     * The value under the primary key; the plaintext is in locked native
     * memory in between, and wiped. A value already under the primary key
     * comes back as it is.
     */
    public byte[] reencrypt(byte[] ciphertext, byte[] context) {
        bound(context);
        if (!needsReencryption(ciphertext)) {
            return ciphertext;
        }
        try (SecretScope plain = SecretScope.allocate(Math.max(1, plaintextLength(ciphertext)))) {
            plain.length(decrypt(ciphertext, context, plain.segment()));
            return encrypt(ring.primary(), plain.secret(), context);
        }
    }

    // ----------------------------------------------------------------- sealed

    /** {@link #encrypt(MemorySegment)} as a {@link Sealed} value; {@code null} for {@code null}. */
    public Sealed seal(MemorySegment plaintext) {
        return plaintext == null ? null : Sealed.of(encrypt(plaintext));
    }

    /** {@link #encrypt(MemorySegment, byte[])} as a {@link Sealed} value. */
    public Sealed seal(MemorySegment plaintext, byte[] context) {
        return plaintext == null ? null : Sealed.of(encrypt(plaintext, context));
    }

    /**
     * Opens a sealed value into native memory the caller owns.
     *
     * @return the length of the plaintext
     * @throws FieldEncryptionException if it is not this column's, or does not authenticate
     */
    public int open(Sealed sealed, MemorySegment target) {
        return open(sealed, NO_CONTEXT, target);
    }

    /** As {@link #open(Sealed, MemorySegment)}, bound to {@code context}. */
    public int open(Sealed sealed, byte[] context, MemorySegment target) {
        if (sealed == null) {
            throw new IllegalArgumentException("nothing to open: a NULL is not sealed");
        }
        return decrypt(sealed.bytes(), context, target);
    }

    /**
     * {@link #searchTerms} as sealed values: the parameter of
     * {@code where e.ssn in :terms} while a rotation is under way.
     */
    public List<Sealed> searchSealed(MemorySegment plaintext) {
        List<Sealed> sealed = new ArrayList<>();
        for (byte[] term : searchTerms(plaintext)) {
            sealed.add(Sealed.of(term));
        }
        return sealed;
    }

    // ------------------------------------------------------------------- JDBC

    /** Binds the encrypted value of native memory; {@code null} binds SQL NULL. */
    public void set(PreparedStatement statement, int index, MemorySegment plaintext)
            throws SQLException {
        set(statement, index, plaintext, NO_CONTEXT);
    }

    /** As {@link #set(PreparedStatement, int, MemorySegment)}, bound to {@code context}. */
    public void set(PreparedStatement statement, int index, MemorySegment plaintext,
            byte[] context) throws SQLException {
        if (plaintext == null) {
            statement.setNull(index, Types.VARBINARY);
            return;
        }
        statement.setBytes(index, encrypted(plaintext, context));
    }

    /**
     * Binds the encrypted value of a {@code String} in UTF-8; {@code null}
     * binds SQL NULL. The text is on the heap already - this keeps it from the
     * database, not from a heap dump.
     */
    public void setString(PreparedStatement statement, int index, String text)
            throws SQLException {
        if (text == null) {
            statement.setNull(index, Types.VARBINARY);
            return;
        }
        // seclume-allow: setString is the heap path by name - the text is a String already
        byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
        try {
            statement.setBytes(index, encrypted(MemorySegment.ofArray(utf8), NO_CONTEXT));
        } finally {
            java.util.Arrays.fill(utf8, (byte) 0);
        }
    }

    /**
     * Reads and decrypts a column into native memory the caller owns.
     *
     * @return the length of the plaintext, or -1 for SQL NULL
     */
    public int readInto(ResultSet rows, int column, MemorySegment target) throws SQLException {
        return readInto(rows, column, NO_CONTEXT, target);
    }

    /** As {@link #readInto(ResultSet, int, MemorySegment)}, bound to {@code context}. */
    public int readInto(ResultSet rows, int column, byte[] context, MemorySegment target)
            throws SQLException {
        byte[] ciphertext = ciphertext(rows, column);
        if (ciphertext == null) {
            return -1;
        }
        try {
            return decrypt(ciphertext, context, target);
        } catch (FieldEncryptionException e) {
            throw new SQLException(e.getMessage(), "22000", e);
        }
    }

    /** How many bytes the current row's value decrypts to, or -1 for SQL NULL - to size a segment. */
    public int length(ResultSet rows, int column) throws SQLException {
        byte[] ciphertext = ciphertext(rows, column);
        if (ciphertext == null) {
            return -1;
        }
        try {
            return plaintextLength(ciphertext);
        } catch (FieldEncryptionException e) {
            throw new SQLException(e.getMessage(), "22000", e);
        }
    }

    /**
     * Reads and decrypts a column as UTF-8 text, on the heap; {@code null} for
     * SQL NULL.
     */
    public String getString(ResultSet rows, int column) throws SQLException {
        byte[] ciphertext = ciphertext(rows, column);
        if (ciphertext == null) {
            return null;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment plain = arena.allocate(Math.max(1, plaintextLength(ciphertext)));
            int length = decrypt(ciphertext, NO_CONTEXT, plain);
            try {
                // seclume-allow: getString is the heap path by name - for data that is a String anyway
                return new String(plain.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                        StandardCharsets.UTF_8);
            } finally {
                plain.fill((byte) 0);
            }
        } catch (FieldEncryptionException e) {
            throw new SQLException(e.getMessage(), "22000", e);
        }
    }

    private byte[] encrypted(MemorySegment plaintext, byte[] context) throws SQLException {
        try {
            return encrypt(plaintext, context);
        } catch (IllegalStateException | FieldEncryptionException e) {
            throw new SQLException(e.getMessage(), "22000", e);
        }
    }

    // ---------------------------------------------------------------- helpers

    /** The stored value: ciphertext, which may be on the heap - it is what the database holds. */
    private static byte[] ciphertext(ResultSet rows, int column) throws SQLException {
        return rows.getBytes(column); // seclume-allow: ciphertext, not a secret
    }

    /** Checks version, flags and key; the key number. */
    private int header(byte[] ciphertext) {
        if (ciphertext == null || ciphertext.length < OVERHEAD) {
            throw new FieldEncryptionException("a value of " + name + " is "
                    + (ciphertext == null ? "missing" : ciphertext.length + " bytes")
                    + ", shorter than any encrypted value (" + OVERHEAD + ")");
        }
        if (ciphertext[0] != VERSION) {
            throw new FieldEncryptionException("a value of " + name + " is not in seclume's "
                    + "field encryption format version 1 - not encrypted, or written by another tool");
        }
        if ((ciphertext[1] & ~PADDED) != mode.flag()) {
            throw new FieldEncryptionException("a value of " + name + " was encrypted "
                    + ((ciphertext[1] & ~PADDED) == Mode.DETERMINISTIC.flag() ? "deterministically"
                            : (ciphertext[1] & ~PADDED) == Mode.RANDOMIZED.flag() ? "randomized"
                                    : "with unknown flags " + (ciphertext[1] & 0xff))
                    + ", the column is " + mode.name().toLowerCase(java.util.Locale.ROOT));
        }
        int keyId = ((ciphertext[2] & 0xff) << 24) | ((ciphertext[3] & 0xff) << 16)
                | ((ciphertext[4] & 0xff) << 8) | (ciphertext[5] & 0xff);
        if (!ring.keyIds().contains(keyId)) {
            throw new FieldEncryptionException("a value of " + name + " is under key " + keyId
                    + ", which the ring does not hold (it holds " + ring.keyIds() + ")");
        }
        return keyId;
    }

    /** HMAC-SHA-256 of the value's header and nonce, under the commitment half of {@code keys}. */
    private static void commitment(MemorySegment keys, MemorySegment value, MemorySegment out,
            long offset) {
        try (space.seclume.crypto.Hmac hmac = new space.seclume.crypto.Hmac(
                space.seclume.crypto.HashAlgorithm.SHA_256, keys, FieldKeys.KEY_LENGTH,
                FieldKeys.KEY_LENGTH)) {
            hmac.update(value, 0, HEADER + AesGcmSiv.NONCE);
            hmac.doFinal(out, offset);
        }
    }

    private MemorySegment columnKey(int keyId) {
        ring.checkOpen();
        SecretScope key = keys.get(keyId);
        if (key == null) {
            throw new FieldEncryptionException("the ring holds no key " + keyId);
        }
        return key.secret();
    }

    private static MemorySegment associatedData(Arena arena, MemorySegment value,
            byte[] context) {
        MemorySegment aad = arena.allocate(HEADER + context.length);
        MemorySegment.copy(value, 0, aad, 0, HEADER);
        MemorySegment.copy(context, 0, aad, ValueLayout.JAVA_BYTE, HEADER, context.length);
        return aad;
    }

    void wipe() {
        keys.values().forEach(SecretScope::close);
    }

    /** The keys derived anew after the ring read its own again; the old ones are wiped already. */
    void rekey(Map<Integer, SecretScope> fresh) {
        keys = fresh;
    }

    @Override
    public String toString() {
        return "EncryptedColumn[" + name + ", " + mode.name().toLowerCase(java.util.Locale.ROOT)
                + "]";
    }
}
