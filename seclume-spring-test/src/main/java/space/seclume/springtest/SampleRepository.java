package space.seclume.springtest;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

/** Nothing of its own: the types are the test, not the queries. */
public interface SampleRepository extends JpaRepository<Sample, UUID> {
}
