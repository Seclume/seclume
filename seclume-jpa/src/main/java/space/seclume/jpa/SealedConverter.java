package space.seclume.jpa;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import space.seclume.field.Sealed;

/**
 * A {@link Sealed} attribute, as the binary value it is, needing no key - a
 * sealed value is ciphertext in the entity, the column only stores it.
 *
 * <pre>
 * &#64;Entity
 * class Tenant {
 *     &#64;Convert(converter = SealedConverter.class)
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
 * <p>Name it on the attribute, as above. It is also {@code autoApply}, for an
 * application that lists it with its entities ({@code managedClass},
 * {@code <class>} in {@code persistence.xml}, or Spring Boot's
 * {@code @EntityScan(basePackageClasses = {App.class, SealedConverter.class})});
 * then a {@code Sealed} attribute needs no {@code @Convert}. A persistence
 * provider does not look into this jar by itself.
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
