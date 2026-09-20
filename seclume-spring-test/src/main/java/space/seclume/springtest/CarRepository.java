package space.seclume.springtest;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * A repository over a subclass - Spring Data adds the discriminator to the
 * where clause, which is the half of single-table inheritance that reads.
 */
public interface CarRepository extends JpaRepository<Car, Long> {

    List<Car> findByLabelStartingWith(String prefix);
}
