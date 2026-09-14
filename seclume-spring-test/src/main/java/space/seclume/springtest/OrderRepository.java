package space.seclume.springtest;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

/** Reads across the foreign key, and one aggregate over a decimal column. */
public interface OrderRepository extends JpaRepository<Order, Long> {

    List<Order> findByCustomerOrderByPlacedAtDesc(Customer customer);

    @org.springframework.data.jpa.repository.Query(
            "select coalesce(sum(o.total), 0) from Order o where o.customer = :customer")
    BigDecimal sumTotalOf(@org.springframework.data.repository.query.Param("customer") Customer customer);
}
