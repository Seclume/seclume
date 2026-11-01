package space.seclume.micronaut;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;

/** A row for Micronaut Data: the repository below maps it, the pool carries it. */
@MappedEntity("zl_mn_patient")
public record DataPatient(@Id Long id, String name, String ward) {
}
