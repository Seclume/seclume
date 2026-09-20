package space.seclume.springtest;

import java.math.BigDecimal;
import java.time.LocalDate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/** A table of its own, with the base columns repeated in it. */
@Entity
@Table(name = "zl_invoice")
public class Invoice extends Doc {

    @Column(name = "net", precision = 12, scale = 2)
    private BigDecimal net;

    protected Invoice() {
    }

    public Invoice(String docNo, LocalDate issuedOn, BigDecimal net) {
        super(docNo, issuedOn);
        this.net = net;
    }

    public BigDecimal getNet() {
        return net;
    }
}
