package space.seclume.jpa;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import space.seclume.field.Sealed;

/**
 * Every {@link Sealed} attribute, as the binary value it is: applied by
 * itself ({@code autoApply}), and needing no key - a sealed value is
 * ciphertext in the entity, the column only stores it.
 *
 * <pre>
 * &#64;Entity
 * class Tenant {
 *     &#64;Column(length = 300)
 *     Sealed apiToken;
 * }
 * </pre>
 *
 * <p>Sealing and opening are the application's, with the
 * {@link space.seclume.field.EncryptedColumn} the value belongs to - so the
 * plaintext is in native memory when it is needed and nowhere else, never in
 * the entity, never on the heap. A deterministic column's sealed values are
 * searched with {@code where t.apiToken = :sealed}.
 *
 * <p>Persistence providers find it by scanning the archive it is in; where they
 * do not, list it with the entities ({@code managedClass}, or
 * {@code <class>} in {@code persistence.xml}).
 */
@Converter(autoApply = true)
public class SealedConverter implements AttributeConverter<Sealed, byte[]> {

    @Override
    public byte[] convertToDatabaseColumn(Sealed attribute) {
        return attribute == null ? null : attribute.ciphertext();
    }

    @Override
    public Sealed convertToEntityAttribute(byte[] stored) {
        return Sealed.of(stored);
    }
}
