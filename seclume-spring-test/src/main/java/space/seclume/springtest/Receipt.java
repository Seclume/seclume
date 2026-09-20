package space.seclume.springtest;

import java.time.LocalDate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/** The second table, so the union has two branches. */
@Entity
@Table(name = "zl_receipt")
public class Receipt extends Doc {

    @Column(name = "cashier", length = 60)
    private String cashier;

    protected Receipt() {
    }

    public Receipt(String docNo, LocalDate issuedOn, String cashier) {
        super(docNo, issuedOn);
        this.cashier = cashier;
    }

    public String getCashier() {
        return cashier;
    }
}
