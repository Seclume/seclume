package space.seclume.springtest;

import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorColumn;
import jakarta.persistence.DiscriminatorType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import jakarta.persistence.Table;

/**
 * Inheritance in one table, told apart by a discriminator column.
 *
 * <p>What the driver has to get right here is not the inheritance - Hibernate
 * resolves that - but the shape of the query it produces: a select whose list
 * holds the columns of <b>all</b> subclasses, most of them null in any given
 * row, and a literal in the where clause that decides the type. A driver that
 * cannot read a null of the right type in the right column returns the wrong
 * class, or nothing.
 *
 * <p>The key is an identity column, which is the strategy that costs the
 * driver the most: the value does not exist until the insert has run, so it
 * comes back through {@code getGeneratedKeys} - four servers, four different
 * ways.
 */
@Entity
@Table(name = "zl_vehicle")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "kind", discriminatorType = DiscriminatorType.STRING, length = 16)
public abstract class Vehicle {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "label", nullable = false, length = 60)
    private String label;

    protected Vehicle() {
    }

    protected Vehicle(String label) {
        this.label = label;
    }

    public Long getId() {
        return id;
    }

    public String getLabel() {
        return label;
    }
}
