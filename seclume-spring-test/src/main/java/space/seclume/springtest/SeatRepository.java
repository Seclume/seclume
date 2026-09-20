package space.seclume.springtest;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

/** A composite key as an id class. */
public interface SeatRepository extends JpaRepository<Seat, SeatId> {

    List<Seat> findBySectionOrderByRowAsc(String section);
}
