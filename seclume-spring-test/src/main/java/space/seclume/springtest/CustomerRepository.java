package space.seclume.springtest;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

/** A derived query, a named one and the inherited ones - the everyday mix. */
public interface CustomerRepository extends JpaRepository<Customer, Long> {

    Optional<Customer> findByEmail(String email);

    List<Customer> findByNameContainingIgnoreCaseOrderByNameAsc(String part);

    @Query("select count(c) from Customer c where c.email like %:domain")
    long countByEmailDomain(@org.springframework.data.repository.query.Param("domain") String domain);
}
