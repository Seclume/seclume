package space.seclume.springtest;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.PrimaryKeyJoinColumn;
import jakarta.persistence.Table;

/** The second joined subclass, so the base table holds rows of both kinds. */
@Entity
@Table(name = "zl_payment_bank")
@PrimaryKeyJoinColumn(name = "payment_id")
public class BankPayment extends Payment {

    @Column(name = "iban", length = 34)
    private String iban;

    protected BankPayment() {
    }

    public BankPayment(java.math.BigDecimal amount, java.time.LocalDateTime paidAt, String iban) {
        super(amount, paidAt);
        this.iban = iban;
    }

    public String getIban() {
        return iban;
    }
}
