package space.seclume.springtest;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

/** Reads across the joined tables. */
public interface PaymentRepository extends JpaRepository<Payment, Long> {

    List<Payment> findAllByOrderByAmountAsc();
}
