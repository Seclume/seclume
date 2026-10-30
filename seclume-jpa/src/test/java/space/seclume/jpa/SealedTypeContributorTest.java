package space.seclume.jpa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

import org.hibernate.boot.model.TypeContributions;
import org.hibernate.boot.model.TypeContributor;
import org.junit.jupiter.api.Test;

/**
 * Hibernate finds {@link SealedTypeContributor} the way it finds every type
 * contributor - {@link ServiceLoader} - and is handed {@link SealedConverter}.
 * That Hibernate then applies it to a {@code Sealed} attribute nobody annotated
 * is {@code JpaFieldEncryptionCase}'s, against the four databases.
 */
class SealedTypeContributorTest {

    @Test
    void hibernateFindsItAndIsHandedTheConverter() {
        List<TypeContributor> found = new ArrayList<>();
        ServiceLoader.load(TypeContributor.class).forEach(found::add);
        assertTrue(found.stream().anyMatch(SealedTypeContributor.class::isInstance),
                "META-INF/services does not name SealedTypeContributor: " + found);

        List<Class<?>> handed = new ArrayList<>();
        new SealedTypeContributor().contribute(new TypeContributions() {
            @Override
            public void contributeAttributeConverter(
                    Class<? extends jakarta.persistence.AttributeConverter<?, ?>> converterClass) {
                handed.add(converterClass);
            }

            @Override
            public org.hibernate.type.spi.TypeConfiguration getTypeConfiguration() {
                return null;
            }
        }, null);
        assertEquals(List.of(SealedConverter.class), handed);
    }
}
