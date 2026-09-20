package space.seclume.springtest;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

/** The whole single-table hierarchy, and one subclass of it on its own. */
public interface VehicleRepository extends JpaRepository<Vehicle, Long> {

    List<Vehicle> findAllByOrderByLabelAsc();
}
