package space.seclume.springtest;

import java.math.BigDecimal;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;

/**
 * Inheritance over joined tables - the base row in one table, the subclass row
 * in another, sharing a key.
 *
 * <p>Every read is a join, every write two inserts inside one transaction, and
 * the second insert uses the key the first produced. That makes this the shape
 * that breaks first when a driver gets batching or generated keys slightly
 * wrong.
 *
 * <p>The key comes from a sequence, which is the third of the four strategies.
 * MySQL has no sequences; Hibernate answers that with a table of its own, and
 * that is the honest outcome to test - the application asks for a sequence and
 * gets working keys on all four.
 */
@Entity
@Table(name = "zl_payment")
@Inheritance(strategy = InheritanceType.JOINED)
@SequenceGenerator(name = "zl_payment_gen", sequenceName = "zl_payment_seq", allocationSize = 1)
public abstract class Payment {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "zl_payment_gen")
    private Long id;

    @Column(name = "amount", nullable = false, precision = 12, scale = 2)
    private BigDecimal amount;

    @Column(name = "paid_at", nullable = false)
    private LocalDateTime paidAt;

    protected Payment() {
    }

    protected Payment(BigDecimal amount, LocalDateTime paidAt) {
        this.amount = amount;
        this.paidAt = paidAt;
    }

    public Long getId() {
        return id;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    public LocalDateTime getPaidAt() {
        return paidAt;
    }
}
