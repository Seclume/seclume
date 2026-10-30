package space.seclume.jpa;

import java.lang.foreign.MemorySegment;

import jakarta.persistence.AttributeConverter;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;

/**
 * A {@code byte[]} attribute stored encrypted - a document, a picture, a
 * binary identifier. One subclass per column, as for
 * {@link EncryptedStringConverter}, whose notes on keys, the heap and
 * searching hold here too.
 */
public abstract class EncryptedBytesConverter implements AttributeConverter<byte[], byte[]> {

    private final String column;
    private final Mode mode;
    private final FieldKeys keys;
    private volatile EncryptedColumn resolved;

    /** With the {@link FieldKeys#installed() installed} ring. */
    protected EncryptedBytesConverter(String column, Mode mode) {
        this(null, column, mode);
    }

    /** With the ring a container hands in. */
    protected EncryptedBytesConverter(FieldKeys keys, String column, Mode mode) {
        if (column == null || column.isBlank() || mode == null) {
            throw new IllegalArgumentException("an encrypted attribute needs its column's name "
                    + "and a mode");
        }
        this.keys = keys;
        this.column = column;
        this.mode = mode;
    }

    /** The column: made on first use, from the ring given or installed. */
    protected final EncryptedColumn column() {
        EncryptedColumn now = resolved;
        if (now == null) {
            now = (keys != null ? keys : FieldKeys.installed()).column(column, mode);
            resolved = now;
        }
        return now;
    }

    @Override
    public byte[] convertToDatabaseColumn(byte[] attribute) {
        return attribute == null ? null : column().encrypt(MemorySegment.ofArray(attribute));
    }

    @Override
    public byte[] convertToEntityAttribute(byte[] stored) {
        if (stored == null) {
            return null;
        }
        EncryptedColumn encrypted = column();
        byte[] plain = new byte[Math.max(0, encrypted.plaintextLength(stored))];
        try {
            encrypted.decrypt(stored, MemorySegment.ofArray(plain));
            return plain;
        } catch (FieldEncryptionException e) {
            throw new FieldEncryptionException(e.getMessage() + " (attribute converted by "
                    + getClass().getName() + ")", e);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + column + ", "
                + mode.name().toLowerCase(java.util.Locale.ROOT) + "]";
    }
}
