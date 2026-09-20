package space.seclume.springtest;

import java.io.Serializable;
import java.util.Objects;

/**
 * The other way of writing a composite key: a plain class named by
 * {@code @IdClass}, whose fields mirror the entity's own.
 *
 * <p>It maps to the same SQL as an {@code @EmbeddedId}, and it is here because
 * applications use both and because Hibernate builds the key differently for
 * each - reading the columns back into a constructor rather than into a field.
 */
public class SeatId implements Serializable {

    private String section;

    private int row;

    public SeatId() {
    }

    public SeatId(String section, int row) {
        this.section = section;
        this.row = row;
    }

    public String getSection() {
        return section;
    }

    public int getRow() {
        return row;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SeatId id
                && row == id.row
                && Objects.equals(section, id.section);
    }

    @Override
    public int hashCode() {
        return Objects.hash(section, row);
    }
}
