package space.seclume.springtest;

import java.math.BigDecimal;

import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;

/** The other half - a decimal column that is null in every car row. */
@Entity
@DiscriminatorValue("TRUCK")
public class Truck extends Vehicle {

    @Column(name = "payload", precision = 10, scale = 2)
    private BigDecimal payload;

    protected Truck() {
    }

    public Truck(String label, BigDecimal payload) {
        super(label);
        this.payload = payload;
    }

    public BigDecimal getPayload() {
        return payload;
    }
}
