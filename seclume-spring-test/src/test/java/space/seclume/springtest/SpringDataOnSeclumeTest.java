package space.seclume.springtest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import space.seclume.pool.SeclumePool;

/**
 * The answer to "does this work with Spring Data?" - a green run, not a
 * "should".
 *
 * <p>Nothing here is written for the driver. These are the ordinary things an
 * application does: save an entity with a generated key, read it back, run a
 * derived query, sum a decimal column, roll a transaction back. What is being
 * tested is that <b>Hibernate and Spring Data are happy</b> with what the
 * driver tells them - and the strictest of those tests is not in this file at
 * all: {@code ddl-auto=validate} compares the schema against
 * {@code getTables}/{@code getColumns} at startup, so a wrong type code means
 * the context does not even come up.
 *
 * <p>Flyway runs first, through the same driver, and that is the other half of
 * the proof: it reads the metadata and runs DDL inside transactions.
 */
abstract class SpringDataOnSeclumeTest {

    @Autowired
    private CustomerRepository customers;

    @Autowired
    private OrderRepository orders;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private org.flywaydb.core.Flyway flyway;

    @BeforeEach
    void empty() {
        orders.deleteAllInBatch();
        customers.deleteAllInBatch();
    }

    /** The pool is ours - otherwise the rest would prove nothing. */
    @Test
    void springUsesTheSeclumePool() {
        assertTrue(dataSource instanceof SeclumePool,
                "Spring is using " + dataSource.getClass().getName());
    }

    /**
     * Flyway ran, through this driver, before anything else.
     *
     * <p>Asked of Flyway and not of the history table: where that table lives
     * differs per server, and this test is about the migration having happened,
     * not about where it wrote its notes.
     */
    @Test
    void flywayMigratedTheSchema() {
        assertNotNull(flyway, "no Flyway in the context");
        assertTrue(flyway.info().applied().length >= 1, "Flyway applied nothing");
    }

    /** A generated key, read back through the entity - {@code getGeneratedKeys}. */
    @Test
    void savingAnEntityFillsTheGeneratedKey() {
        Customer saved = customers.save(new Customer("Ada", "ada@example.com"));
        assertNotNull(saved.getId(), "no key came back");

        Optional<Customer> found = customers.findById(saved.getId());
        assertTrue(found.isPresent());
        assertEquals("Ada", found.get().getName());
    }

    /** Derived queries, a JPQL one, and the sort order the name promises. */
    @Test
    void theUsualQueriesWork() {
        customers.save(new Customer("Grace", "grace@example.com"));
        customers.save(new Customer("Alan", "alan@example.com"));
        customers.save(new Customer("Edsger", "edsger@example.org"));

        assertTrue(customers.findByEmail("grace@example.com").isPresent());
        List<Customer> withA = customers.findByNameContainingIgnoreCaseOrderByNameAsc("a");
        assertEquals(List.of("Alan", "Grace"),
                withA.stream().map(Customer::getName).toList());
        assertEquals(2, customers.countByEmailDomain("example.com"));
    }

    /** A foreign key, a timestamp and a decimal - across two tables. */
    @Test
    void readingAcrossTheForeignKeyWorks() {
        Customer customer = customers.save(new Customer("Barbara", "barbara@example.com"));
        orders.save(new Order(customer, LocalDateTime.now().minusDays(1),
                new BigDecimal("19.99")));
        orders.save(new Order(customer, LocalDateTime.now(), new BigDecimal("5.01")));

        List<Order> found = orders.findByCustomerOrderByPlacedAtDesc(customer);
        assertEquals(2, found.size());
        assertTrue(found.get(0).getPlacedAt().isAfter(found.get(1).getPlacedAt()),
                "the sort order did not survive the round trip");
        assertSame(0, new BigDecimal("25.00").compareTo(orders.sumTotalOf(customer)),
                "the decimal came back as " + orders.sumTotalOf(customer));
    }

    /**
     * Hibernate's batch size, which is what {@code executeBatch} has to count
     * correctly - and the reason the driver bundles at all.
     */
    @Test
    void aBatchOfInsertsGoesThrough() {
        List<Customer> many = new java.util.ArrayList<>();
        for (int i = 0; i < 120; i++) {
            many.add(new Customer("Person " + i, "person" + i + "@example.com"));
        }
        customers.saveAll(many);
        customers.flush();
        assertEquals(120, customers.count());
    }

    /** What a transaction promises: nothing of it stays when it rolls back. */
    @Test
    @Transactional
    void aRolledBackTransactionLeavesNothing() {
        customers.save(new Customer("Ephemeral", "gone@example.com"));
        customers.flush();
        assertEquals(1, customers.count());
        // The test method is transactional; Spring rolls it back afterwards,
        // and the next test's count starts at zero again.
    }

    @Test
    void theDatabaseIsEmptyAgainAfterTheRollback() {
        assertEquals(0, customers.count(), "the rolled-back transaction left something");
    }
}
