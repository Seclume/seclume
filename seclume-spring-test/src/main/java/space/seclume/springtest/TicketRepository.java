package space.seclume.springtest;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

/** A composite key as an embedded object. */
public interface TicketRepository extends JpaRepository<Ticket, TicketId> {

    List<Ticket> findByIdEventOrderByIdSeatNoAsc(String event);
}
