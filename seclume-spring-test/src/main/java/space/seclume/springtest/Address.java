package space.seclume.springtest;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/**
 * An {@code @Embeddable} - two columns of the customer's table that the
 * application sees as one object.
 *
 * <p>Nothing about it is driver-specific, which is the point: if the columns
 * are read and written correctly, an embedded value costs the driver nothing.
 * It is here because {@code ddl-auto=validate} checks its columns too, and
 * because an application that uses one would notice at once if it did not
 * work.
 */
@Embeddable
public class Address {

    @Column(length = 100)
    private String street;

    @Column(length = 100)
    private String city;

    protected Address() {
    }

    public Address(String street, String city) {
        this.street = street;
        this.city = city;
    }

    public String getStreet() {
        return street;
    }

    public String getCity() {
        return city;
    }
}
