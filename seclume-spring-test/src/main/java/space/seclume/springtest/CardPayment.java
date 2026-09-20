package space.seclume.springtest;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.PrimaryKeyJoinColumn;
import jakarta.persistence.Table;

/** A joined subclass - its own table, keyed by the base row's key. */
@Entity
@Table(name = "zl_payment_card")
@PrimaryKeyJoinColumn(name = "payment_id")
public class CardPayment extends Payment {

    @Column(name = "last_four", length = 4)
    private String lastFour;

    protected CardPayment() {
    }

    public CardPayment(java.math.BigDecimal amount, java.time.LocalDateTime paidAt, String lastFour) {
        super(amount, paidAt);
        this.lastFour = lastFour;
    }

    public String getLastFour() {
        return lastFour;
    }
}
