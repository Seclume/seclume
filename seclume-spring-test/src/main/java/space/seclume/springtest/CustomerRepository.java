package space.seclume.springtest;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

/**
 * The annotations an application actually uses, one of each.
 *
 * <p>This is not a repository anybody would write for one entity - it is the
 * list of things Spring Data turns into SQL, gathered in one place so that a
 * single test run says whether they all reach the four servers correctly.
 * Each one asks something different of the driver, and the ones worth naming
 * are:
 *
 * <ul>
 *   <li>a <b>native</b> query, which is SQL the driver gets unchanged - so
 *       the placeholder rewriting and the column types are ours alone;</li>
 *   <li>a <b>modifying</b> query, whose return value is the update count;</li>
 *   <li><b>paging</b>, which becomes the server's own limit syntax and a
 *       second count query;</li>
 *   <li>a <b>pessimistic lock</b>, which becomes {@code for update} or the
 *       server's equivalent and would fail loudly if the driver mangled
 *       it;</li>
 *   <li>a <b>stream</b>, which holds a cursor open across the read.</li>
 * </ul>
 */
public interface CustomerRepository extends JpaRepository<Customer, Long>,
        JpaSpecificationExecutor<Customer> {

    Optional<Customer> findByEmail(String email);

    List<Customer> findByNameContainingIgnoreCaseOrderByNameAsc(String part);

    @Query("select count(c) from Customer c where c.email like %:domain")
    long countByEmailDomain(@Param("domain") String domain);

    // ---- the annotation sweep ---------------------------------------------

    boolean existsByEmail(String email);

    long countByStatus(CustomerStatus status);

    List<Customer> findByStatus(CustomerStatus status);

    /** Derived deletion - several statements, and the count of what went. */
    long deleteByStatus(CustomerStatus status);

    /** A page: the server's limit syntax plus a count query. */
    Page<Customer> findByStatus(CustomerStatus status, Pageable page);

    /** A slice: the same without the count, which is one round trip less. */
    Slice<Customer> findByNameStartingWith(String prefix, Pageable page);

    /**
     * SQL the driver gets exactly as written.
     *
     * <p>{@code {h-schema}} is Hibernate's placeholder for the default
     * schema and it is not decoration: the PostgreSQL profile puts this
     * application in a schema of its own, so unqualified native SQL looks
     * for the table in {@code public} and does not find it. JPA queries are
     * qualified by Hibernate; native ones are the application's own
     * business, and this is how one says "wherever my tables are".
     */
    @Query(value = "select * from {h-schema}zl_customer where email = :email",
            nativeQuery = true)
    Optional<Customer> findByEmailNatively(@Param("email") String email);

    /** A native aggregate, which comes back as a plain number rather than an entity. */
    @Query(value = "select count(*) from {h-schema}zl_customer where status = :status",
            nativeQuery = true)
    long countByStatusNatively(@Param("status") String status);

    /** An update, whose answer is the number of rows the server reported. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update Customer c set c.status = :status where c.email like %:domain")
    int markDomain(@Param("domain") String domain, @Param("status") CustomerStatus status);

    /** A projection - Spring builds it from the columns, so the types have to be right. */
    @Query("select c.name as name, c.email as email from Customer c where c.status = :status")
    List<NameAndEmail> namesOf(@Param("status") CustomerStatus status);

    /** An entity graph, which turns a second query into a join. */
    @EntityGraph(attributePaths = "address")
    Optional<Customer> findWithAddressByEmail(String email);

    /** {@code select ... for update}, or whatever the server spells it. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from Customer c where c.email = :email")
    Optional<Customer> lockByEmail(@Param("email") String email);

    /** A cursor held open while the rows are read. */
    @Query("select c from Customer c where c.status = :status")
    Stream<Customer> streamByStatus(@Param("status") CustomerStatus status);

    /** What a projection looks like: an interface, filled from the aliases. */
    interface NameAndEmail {
        String getName();

        String getEmail();
    }
}
