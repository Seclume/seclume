package space.seclume.r2dbc;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import io.r2dbc.spi.Readable;
import io.r2dbc.spi.Statement;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldEncryptionException;

/**
 * Field encryption for R2DBC: a value bound encrypted, a value read and
 * decrypted - in the same format as through JDBC, so that a row written by one
 * is read by the other. The ciphertext is a {@code ByteBuffer}, which any
 * R2DBC driver binds and reads; the plaintext is in native memory at both ends.
 *
 * <pre>
 * EncryptedColumn token = keys.column("tenant.api_token", Mode.RANDOMIZED);
 * EncryptedValues.bind(connection.createStatement("insert into tenant (id, api_token) values ($1, $2)")
 *         .bind(0, id), 1, token, issued.secret());
 * ...
 * Flux.from(result.map((row, meta) -&gt; EncryptedValues.readInto(row, "api_token", token, value.segment())));
 * </pre>
 */
public final class EncryptedValues {

    private EncryptedValues() {
    }

    /** Binds the encrypted value of native memory at {@code index}; {@code null} binds NULL. */
    public static Statement bind(Statement statement, int index, EncryptedColumn column,
            MemorySegment plaintext) {
        return plaintext == null ? statement.bindNull(index, ByteBuffer.class)
                : statement.bind(index, ByteBuffer.wrap(column.encrypt(plaintext)));
    }

    /** As {@link #bind(Statement, int, EncryptedColumn, MemorySegment)}, by name. */
    public static Statement bind(Statement statement, String name, EncryptedColumn column,
            MemorySegment plaintext) {
        return plaintext == null ? statement.bindNull(name, ByteBuffer.class)
                : statement.bind(name, ByteBuffer.wrap(column.encrypt(plaintext)));
    }

    /**
     * Decrypts the value at {@code index} into native memory the caller owns.
     *
     * @return the length of the plaintext, or -1 for NULL
     * @throws FieldEncryptionException if it is not this column's, or does not authenticate
     */
    public static int readInto(Readable row, int index, EncryptedColumn column,
            MemorySegment target) {
        return decrypt(row.get(index, ByteBuffer.class), column, target);
    }

    /** As {@link #readInto(Readable, int, EncryptedColumn, MemorySegment)}, by name. */
    public static int readInto(Readable row, String name, EncryptedColumn column,
            MemorySegment target) {
        return decrypt(row.get(name, ByteBuffer.class), column, target);
    }

    /** How many bytes the value at {@code index} decrypts to, or -1 for NULL. */
    public static int length(Readable row, int index, EncryptedColumn column) {
        ByteBuffer stored = row.get(index, ByteBuffer.class);
        return stored == null ? -1 : column.plaintextLength(bytes(stored));
    }

    private static int decrypt(ByteBuffer stored, EncryptedColumn column, MemorySegment target) {
        return stored == null ? -1 : column.decrypt(bytes(stored), target);
    }

    /** The ciphertext - which may be on the heap: it is what the database holds. */
    private static byte[] bytes(ByteBuffer stored) {
        ByteBuffer copy = stored.duplicate();
        byte[] bytes = new byte[copy.remaining()]; // seclume-allow: ciphertext, not a secret
        copy.get(bytes);
        return bytes;
    }
}
