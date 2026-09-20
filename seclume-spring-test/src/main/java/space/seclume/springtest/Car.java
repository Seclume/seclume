package space.seclume.springtest;

import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;

/** One half of the single-table hierarchy. */
@Entity
@DiscriminatorValue("CAR")
public class Car extends Vehicle {

    @Column(name = "seats")
    private Integer seats;

    protected Car() {
    }

    public Car(String label, int seats) {
        super(label);
        this.seats = seats;
    }

    public Integer getSeats() {
        return seats;
    }
}
