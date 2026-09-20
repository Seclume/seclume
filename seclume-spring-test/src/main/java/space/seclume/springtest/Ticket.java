package space.seclume.springtest;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/** An entity whose key is an {@code @EmbeddedId}. */
@Entity
@Table(name = "zl_ticket")
public class Ticket {

    @EmbeddedId
    private TicketId id;

    @Column(name = "holder", length = 60)
    private String holder;

    protected Ticket() {
    }

    public Ticket(TicketId id, String holder) {
        this.id = id;
        this.holder = holder;
    }

    public TicketId getId() {
        return id;
    }

    public String getHolder() {
        return holder;
    }
}
