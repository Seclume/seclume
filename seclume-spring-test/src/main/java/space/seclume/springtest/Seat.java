package space.seclume.springtest;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

/**
 * An entity with an {@code @IdClass} - two {@code @Id} fields, no embedded
 * object.
 *
 * <p>The column is {@code seat_row}, not {@code row}: that word is taken on
 * more than one of the four servers, and a mapping that only works on some of
 * them would not prove anything.
 */
@Entity
@Table(name = "zl_seat")
@IdClass(SeatId.class)
public class Seat {

    @Id
    @Column(name = "section_name", length = 20)
    private String section;

    @Id
    @Column(name = "seat_row")
    private int row;

    @Column(name = "note", length = 60)
    private String note;

    protected Seat() {
    }

    public Seat(String section, int row, String note) {
        this.section = section;
        this.row = row;
        this.note = note;
    }

    public String getSection() {
        return section;
    }

    public int getRow() {
        return row;
    }

    public String getNote() {
        return note;
    }
}
