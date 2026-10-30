package space.seclume.jpa;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import jakarta.persistence.AttributeConverter;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;

/**
 * A {@code String} attribute stored encrypted: one subclass per column, which
 * names it and its mode, because a converter is not told which attribute it
 * converts and the column's name is part of its key.
 *
 * <pre>
 * &#64;Converter
 * public class SsnConverter extends EncryptedStringConverter {
 *     public SsnConverter() {
 *         super("patient.ssn", Mode.DETERMINISTIC);
 *     }
 * }
 *
 * &#64;Entity
 * class Patient {
 *     &#64;Convert(converter = SsnConverter.class)
 *     &#64;Column(length = 64, unique = true)
 *     String ssn;
 * }
 *
 * List&lt;Patient&gt; found = em.createQuery("from Patient where ssn = :ssn", Patient.class)
 *         .setParameter("ssn", "078-05-1120").getResultList();
 * </pre>
 *
 * <p>The keys are the ring {@link FieldKeys#install installed} - the Spring
 * Boot starter installs the one it builds from
 * {@code seclume.field-encryption.keys.*} - looked up when the first value is
 * converted, not when the converter is made: a persistence provider makes its
 * converters before an application has read its keys. A container that
 * injects converters (Spring's bean container for Hibernate, CDI) can hand the
 * ring in through {@link #EncryptedStringConverter(FieldKeys, String, Mode)}.
 *
 * <p><b>The text is on the heap</b>, as every {@code String} attribute is:
 * this keeps it from the database, its backups and its administrators, not
 * from a heap dump. A secret the application only passes on - a token, a key -
 * belongs in a {@link space.seclume.field.Sealed} attribute instead.
 *
 * <p>A deterministic column is searched by equality - JPQL {@code =} and
 * {@code in}, derived queries such as {@code findBySsn} - because the provider
 * converts the parameter as it converts the attribute. While a rotation is
 * under way, only values under the primary key are found that way; see
 * {@link EncryptedColumn#searchSealed}.
 */
public abstract class EncryptedStringConverter implements AttributeConverter<String, byte[]> {

    private final String column;
    private final Mode mode;
    private final FieldKeys keys;
    private volatile EncryptedColumn resolved;

    /** With the {@link FieldKeys#installed() installed} ring. */
    protected EncryptedStringConverter(String column, Mode mode) {
        this(null, column, mode);
    }

    /** With the ring a container hands in. */
    protected EncryptedStringConverter(FieldKeys keys, String column, Mode mode) {
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
    public byte[] convertToDatabaseColumn(String attribute) {
        if (attribute == null) {
            return null;
        }
        // seclume-allow: the attribute is a String already - this keeps it from the database
        byte[] utf8 = attribute.getBytes(StandardCharsets.UTF_8);
        try {
            return column().encrypt(MemorySegment.ofArray(utf8));
        } finally {
            Arrays.fill(utf8, (byte) 0);
        }
    }

    @Override
    public String convertToEntityAttribute(byte[] stored) {
        if (stored == null) {
            return null;
        }
        EncryptedColumn encrypted = column();
        byte[] plain = new byte[Math.max(0, encrypted.plaintextLength(stored))];
        try {
            int length = encrypted.decrypt(stored, MemorySegment.ofArray(plain));
            // seclume-allow: a String attribute - the heap path by name
            return new String(plain, 0, length, StandardCharsets.UTF_8);
        } catch (FieldEncryptionException e) {
            throw new FieldEncryptionException(e.getMessage() + " (attribute converted by "
                    + getClass().getName() + ")", e);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + column + ", "
                + mode.name().toLowerCase(java.util.Locale.ROOT) + "]";
    }
}
