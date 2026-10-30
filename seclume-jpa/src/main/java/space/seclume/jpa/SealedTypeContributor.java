package space.seclume.jpa;

import org.hibernate.boot.model.TypeContributions;
import org.hibernate.boot.model.TypeContributor;
import org.hibernate.service.ServiceRegistry;

/**
 * Registers {@link SealedConverter} with Hibernate wherever Hibernate starts,
 * found through {@code META-INF/services}: a {@link space.seclume.field.Sealed}
 * attribute then needs no {@code @Convert}, and the converter no listing next
 * to the entities - Spring Boot's entity scan, for one, never looks into this
 * jar. Another persistence provider never loads this class; there, list the
 * converter or name it with {@code @Convert}.
 */
public final class SealedTypeContributor implements TypeContributor {

    @Override
    public void contribute(TypeContributions typeContributions, ServiceRegistry serviceRegistry) {
        typeContributions.contributeAttributeConverter(SealedConverter.class);
    }
}
