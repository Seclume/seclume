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
    private final Map<Integer, SecretScope> keys;

    EncryptedColumn(FieldKeys ring, String name, Mode mode, Map<Integer, SecretScope> keys) {
        this.ring = ring;
        this.name = name;
        this.mode = mode;
        this.keys = keys;
    }

    public String name() {
        return name;
    }

    public Mode mode() {
        return mode;
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
        byte[] context0 = context == null ? NO_CONTEXT : context;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment value = arena.allocate(OVERHEAD + length);
            value.set(ValueLayout.JAVA_BYTE, 0, VERSION);
            value.set(ValueLayout.JAVA_BYTE, 1, mode.flag());
            value.set(BE_INT, 2, keyId);
            if (mode == Mode.RANDOMIZED) {
                Entropy.fill(value, HEADER, AesGcmSiv.NONCE);
            }
            MemorySegment aad = associatedData(arena, value, context0);
            ring.lock().lock();
            try {
                MemorySegment keys = columnKey(keyId);
                commitment(keys, value, value, HEADER + AesGcmSiv.NONCE);
                AesGcmSiv.encrypt(keys, 0, FieldKeys.KEY_LENGTH,
                        value, HEADER, aad, 0, aad.byteSize(),
                        plaintext, 0, length, value, BODY);
            } finally {
                ring.lock().unlock();
            }
            return value.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /** How many bytes {@code ciphertext} decrypts to; checks only the format. */
    public int plaintextLength(byte[] ciphertext) {
        header(ciphertext);
        return ciphertext.length - OVERHEAD;
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
        if (target.byteSize() < length) {
            throw new FieldEncryptionException("the value of " + name + " is " + length
                    + " bytes and does not fit into " + target.byteSize());
        }
        byte[] context0 = context == null ? NO_CONTEXT : context;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment value = arena.allocate(ciphertext.length);
            MemorySegment.copy(ciphertext, 0, value, ValueLayout.JAVA_BYTE, 0, ciphertext.length);
            MemorySegment aad = associatedData(arena, value, context0);
            boolean authentic;
            ring.lock().lock();
            try {
                MemorySegment keys = columnKey(keyId);
                // The commitment first: a value made under another key - one that
                // happens to open under this one too - is refused before AES-GCM-SIV
                // is asked, and with the same words, so that neither check is an oracle.
                MemorySegment expected = arena.allocate(COMMITMENT);
                commitment(keys, value, expected, 0);
                authentic = space.seclume.crypto.ConstantTime.equals(expected, 0, value,
                        HEADER + AesGcmSiv.NONCE, COMMITMENT)
                        && AesGcmSiv.decrypt(keys, 0, FieldKeys.KEY_LENGTH,
                                value, HEADER, aad, 0, aad.byteSize(),
                                value, BODY, length, target, 0);
            } finally {
                ring.lock().unlock();
            }
            if (!authentic) {
                throw new FieldEncryptionException("a value of " + name + " did not authenticate"
                        + " - another column's, another row's context, or altered");
            }
            return length;
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
        return header(ciphertext) != ring.primary();
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
        if (ciphertext[1] != mode.flag()) {
            throw new FieldEncryptionException("a value of " + name + " was encrypted "
                    + (ciphertext[1] == Mode.DETERMINISTIC.flag() ? "deterministically"
                            : ciphertext[1] == Mode.RANDOMIZED.flag() ? "randomized"
                                    : "with unknown flags " + (ciphertext[1] & 0xff))
                    + ", the column is " + mode.name().toLowerCase(java.util.Locale.ROOT));
        }
        int keyId = ((ciphertext[2] & 0xff) << 24) | ((ciphertext[3] & 0xff) << 16)
                | ((ciphertext[4] & 0xff) << 8) | (ciphertext[5] & 0xff);
        if (!keys.containsKey(keyId)) {
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

    @Override
    public String toString() {
        return "EncryptedColumn[" + name + ", " + mode.name().toLowerCase(java.util.Locale.ROOT)
                + "]";
    }
}
