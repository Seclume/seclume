package space.seclume.springtest;

import java.math.BigDecimal;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/** A foreign key, a timestamp and a decimal - three types that go wrong easily. */
@Entity
@Table(name = "zl_order")
public class Order {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "customer_id", nullable = false)
    private Customer customer;

    @Column(name = "placed_at", nullable = false)
    private LocalDateTime placedAt;

    @Column(nullable = false)
    private BigDecimal total;

    protected Order() {
    }

    public Order(Customer customer, LocalDateTime placedAt, BigDecimal total) {
        this.customer = customer;
        this.placedAt = placedAt;
        this.total = total;
    }

    public Long getId() {
        return id;
    }

    public Customer getCustomer() {
        return customer;
    }

    public LocalDateTime getPlacedAt() {
        return placedAt;
    }

    public BigDecimal getTotal() {
        return total;
    }
}
