package space.seclume.springtest;

import java.io.Serializable;
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/**
 * The key of a ticket - two columns the application sees as one value.
 *
 * <p>For the driver this means every read of one row binds two parameters and
 * compares two columns, and every {@code findById} sends a composite where
 * clause. It is also the shape that exposes a wrong equality: if a string
 * comes back padded or a number comes back as a different width, the entity
 * is loaded but never found again in the persistence context.
 */
@Embeddable
public class TicketId implements Serializable {

    @Column(name = "event_name", nullable = false, length = 40)
    private String event;

    @Column(name = "seat_no", nullable = false)
    private int seatNo;

    protected TicketId() {
    }

    public TicketId(String event, int seatNo) {
        this.event = event;
        this.seatNo = seatNo;
    }

    public String getEvent() {
        return event;
    }

    public int getSeatNo() {
        return seatNo;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof TicketId id
                && seatNo == id.seatNo
                && Objects.equals(event, id.event);
    }

    @Override
    public int hashCode() {
        return Objects.hash(event, seatNo);
    }
}
