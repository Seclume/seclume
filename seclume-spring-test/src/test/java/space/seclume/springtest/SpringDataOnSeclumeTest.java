package space.seclume.springtest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.Year;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Sort;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
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
    private SampleRepository samples;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private org.flywaydb.core.Flyway flyway;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entities;

    @BeforeEach
    void empty() {
        orders.deleteAllInBatch();
        customers.deleteAllInBatch();
        samples.deleteAllInBatch();
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


    // ---- the annotation sweep ---------------------------------------------

    /**
     * {@code @Version}: the second writer of a row is told, not ignored.
     *
     * <p>This is the strictest test of the driver's update count there is.
     * Hibernate writes {@code where id = ? and version = ?} and decides from
     * <b>the number of rows it changed</b> whether somebody else got there
     * first. A driver that reports one row too many never throws, and every
     * lost update passes unnoticed; one too few and every second save fails.
     */
    @Test
    void optimisticLockingNoticesTheSecondWriter() {
        Customer saved = customers.saveAndFlush(new Customer("Vera", "vera@example.com"));
        assertEquals(0L, saved.getVersion(), "a fresh row starts at version 0");

        Customer stale = customers.findById(saved.getId()).orElseThrow();
        entities.detach(stale);

        saved.setName("Vera the first");
        // The instance that comes back, not the one that went in: outside a
        // transaction the entity is detached after the first save, so this is
        // a merge and the managed copy is what carries the new version.
        Customer written = customers.saveAndFlush(saved);
        assertEquals(1L, written.getVersion(), "the version did not move");

        stale.setName("Vera the second");
        assertThrows(ObjectOptimisticLockingFailureException.class,
                () -> customers.saveAndFlush(stale),
                "the stale write was accepted - the update count is wrong");
    }

    /** {@code @CreatedDate} and {@code @LastModifiedDate}, through four column types. */
    @Test
    void auditingFillsTheTimestampsAndUpdatesTheSecond() throws Exception {
        Customer saved = customers.saveAndFlush(new Customer("Audit", "audit@example.com"));
        assertNotNull(saved.getCreatedAt(), "@CreatedDate stayed empty");
        assertNotNull(saved.getUpdatedAt(), "@LastModifiedDate stayed empty");
        LocalDateTime created = saved.getCreatedAt();

        Thread.sleep(20);
        saved.setName("Audited");
        customers.saveAndFlush(saved);
        entities.clear();

        Customer read = customers.findById(saved.getId()).orElseThrow();
        assertEquals(created.truncatedTo(ChronoUnit.MILLIS),
                read.getCreatedAt().truncatedTo(ChronoUnit.MILLIS),
                "the created timestamp moved");
        assertTrue(read.getUpdatedAt().isAfter(read.getCreatedAt().minusSeconds(1)),
                "the modified timestamp did not come back");
    }

    /** {@code @Enumerated(STRING)}, {@code @Embedded} and {@code @Lob} in one row. */
    @Test
    void anEnumAnEmbeddedValueAndALargeTextSurviveTheRoundTrip() {
        Customer customer = new Customer("Lob", "lob@example.com");
        customer.setStatus(CustomerStatus.DORMANT);
        customer.setAddress(new Address("Hauptstrasse 1", "Wien"));
        customer.setNotes("x".repeat(20_000));
        customers.saveAndFlush(customer);
        entities.clear();

        Customer read = customers.findById(customer.getId()).orElseThrow();
        assertEquals(CustomerStatus.DORMANT, read.getStatus());
        assertEquals("Hauptstrasse 1", read.getAddress().getStreet());
        assertEquals("Wien", read.getAddress().getCity());
        assertEquals(20_000, read.getNotes().length(), "the large text came back short");
        assertEquals(1, customers.countByStatus(CustomerStatus.DORMANT));
        assertEquals(1, customers.countByStatusNatively("DORMANT"),
                "the enum is not stored as its name");
    }

    /** A native query: SQL the driver gets unchanged, mapped back to an entity. */
    @Test
    void aNativeQueryReturnsAnEntity() {
        customers.saveAndFlush(new Customer("Native", "native@example.com"));
        entities.clear();

        Customer read = customers.findByEmailNatively("native@example.com").orElseThrow();
        assertEquals("Native", read.getName());
        assertTrue(customers.existsByEmail("native@example.com"));
    }

    /** {@code @Modifying}: the answer is the number of rows the server reported. */
    @Test
    @Transactional
    void aModifyingQueryAnswersWithTheNumberOfRowsItChanged() {
        customers.save(new Customer("One", "one@example.com"));
        customers.save(new Customer("Two", "two@example.com"));
        customers.save(new Customer("Three", "three@example.org"));
        customers.flush();

        assertEquals(2, customers.markDomain("example.com", CustomerStatus.CLOSED),
                "the update count is wrong");
        assertEquals(2, customers.countByStatus(CustomerStatus.CLOSED));
    }

    /** Paging and sorting: the server's own limit syntax, and a count query with it. */
    @Test
    void paginationAndSortingComeBackInTheRightOrder() {
        for (int i = 0; i < 7; i++) {
            customers.save(new Customer("Page " + i, "page" + i + "@example.com"));
        }
        customers.flush();

        Page<Customer> second = customers.findByStatus(CustomerStatus.ACTIVE,
                PageRequest.of(1, 3, Sort.by("name").ascending()));
        assertEquals(7, second.getTotalElements(), "the count query is wrong");
        assertEquals(3, second.getNumberOfElements());
        assertEquals(List.of("Page 3", "Page 4", "Page 5"),
                second.getContent().stream().map(Customer::getName).toList());

        Slice<Customer> slice = customers.findByNameStartingWith("Page",
                PageRequest.of(2, 3, Sort.by("name").ascending()));
        assertEquals(1, slice.getNumberOfElements(), "the last slice is the remainder");
        assertFalse(slice.hasNext());
    }

    /** A projection, a specification and an entity graph - three ways to shape a read. */
    @Test
    void projectionsSpecificationsAndEntityGraphsWork() {
        Customer one = new Customer("Spec", "spec@example.com");
        one.setAddress(new Address("Ringstrasse 2", "Graz"));
        customers.saveAndFlush(one);
        customers.saveAndFlush(new Customer("Other", "other@example.org"));
        entities.clear();

        List<CustomerRepository.NameAndEmail> names = customers.namesOf(CustomerStatus.ACTIVE);
        assertEquals(2, names.size());
        assertTrue(names.stream().anyMatch(n -> "spec@example.com".equals(n.getEmail())
                && "Spec".equals(n.getName())), "the projection came back empty");

        List<Customer> found = customers.findAll((root, query, builder) ->
                builder.like(root.get("email"), "%example.com"));
        assertEquals(List.of("Spec"), found.stream().map(Customer::getName).toList());

        Customer withAddress = customers.findWithAddressByEmail("spec@example.com")
                .orElseThrow();
        assertEquals("Graz", withAddress.getAddress().getCity());
    }

    /**
     * A pessimistic lock and a streamed read, both inside one transaction.
     *
     * <p>The lock becomes {@code for update} or whatever the server spells it
     * with, and a driver that mangled the statement would be told so by the
     * server rather than quietly locking nothing. The stream holds a cursor
     * open while the rows are read, which is the case that breaks when a
     * driver reads everything eagerly and closes.
     */
    @Test
    @Transactional
    void aPessimisticLockAndAStreamedReadWork() {
        customers.save(new Customer("Locked", "locked@example.com"));
        for (int i = 0; i < 5; i++) {
            customers.save(new Customer("Streamed " + i, "stream" + i + "@example.com"));
        }
        customers.flush();

        assertTrue(customers.lockByEmail("locked@example.com").isPresent(),
                "the locking read came back empty");

        try (Stream<Customer> rows = customers.streamByStatus(CustomerStatus.ACTIVE)) {
            assertEquals(6, rows.count(), "the stream lost rows");
        }
    }

    /** A derived deletion, which is several statements and a count. */
    @Test
    @Transactional
    void aDerivedDeletionRemovesExactlyItsOwn() {
        Customer closed = new Customer("Gone", "gone@example.com");
        closed.setStatus(CustomerStatus.CLOSED);
        customers.save(closed);
        customers.save(new Customer("Stays", "stays@example.com"));
        customers.flush();

        assertEquals(1, customers.deleteByStatus(CustomerStatus.CLOSED));
        customers.flush();
        assertEquals(1, customers.count());
    }


    /**
     * One row of every type an application maps, written and read back.
     *
     * <p>Values are chosen to catch the ordinary mistakes rather than to look
     * plausible: a negative number, a decimal whose scale matters, a time
     * with no date, a point on the time line with an offset that is not the
     * machine's, a duration that is not a whole number of seconds, bytes that
     * include a zero and a high bit.
     *
     * <p>What each server stores is its own business - a {@code UUID} is
     * sixteen bytes here, a string of thirty-six there - and the test says
     * nothing about that. It says that what went in comes back.
     */
    @Test
    void everyMappedJavaTypeSurvivesTheRoundTrip() {
        Sample written = new Sample(true, (short) -12345, -2_000_000_000, 9_007_199_254_740_993L,
                -0.5d, new BigDecimal("12345678901234.5678"), "Grüße, Ada",
                new byte[] {0, 1, -128, 127, 42}, LocalDate.of(1970, 1, 1),
                LocalTime.of(23, 59, 59), LocalDateTime.of(2026, 9, 20, 11, 29, 16, 153_000_000),
                Instant.parse("2026-09-20T09:29:16.153Z"),
                OffsetDateTime.parse("2026-09-20T11:29:16.153+02:00"),
                Duration.ofSeconds(90, 500_000_000), Year.of(2026), CustomerStatus.DORMANT,
                new Money(new BigDecimal("19.99"), "EUR"));
        Sample saved = samples.saveAndFlush(written);
        assertNotNull(saved.getId(), "the UUID key was not generated");
        entities.clear();

        Sample read = samples.findById(saved.getId()).orElseThrow();
        assertTrue(read.isFlag());
        assertEquals((short) -12345, read.getSmall());
        assertEquals(-2_000_000_000, read.getNumber());
        assertEquals(9_007_199_254_740_993L, read.getBig(),
                "a long beyond a double's precision came back rounded");
        assertEquals(-0.5d, read.getPrecise());
        assertEquals(0, new BigDecimal("12345678901234.5678").compareTo(read.getAmount()),
                "the decimal came back as " + read.getAmount());
        assertEquals("Grüße, Ada", read.getText(), "the text is not round-tripped as UTF-8");
        assertArrayEquals(new byte[] {0, 1, -128, 127, 42}, read.getRaw());
        assertEquals(LocalDate.of(1970, 1, 1), read.getDay());
        assertEquals(LocalTime.of(23, 59, 59), read.getMoment());
        assertEquals(LocalDateTime.of(2026, 9, 20, 11, 29, 16, 153_000_000), read.getStamp(),
                "the fraction of a second was lost");
        assertEquals(Instant.parse("2026-09-20T09:29:16.153Z"), read.getInstant());
        assertEquals(OffsetDateTime.parse("2026-09-20T11:29:16.153+02:00").toInstant(),
                read.getOffset().toInstant(), "the offset moved the point in time");
        assertEquals(Duration.ofSeconds(90, 500_000_000), read.getDuration());
        assertEquals(Year.of(2026), read.getYear());
        assertEquals(CustomerStatus.DORMANT, read.getStatus());
        assertEquals(new Money(new BigDecimal("19.99"), "EUR"), read.getPrice(),
                "the converter's value did not survive");
    }

    /** Null in every column that allows it - a different path from a value. */
    @Test
    void everyNullableTypeCanBeNull() {
        Sample written = new Sample(false, (short) 0, 0, 0L, 0d, null, null, null, null, null,
                null, null, null, null, null, null, null);
        Sample saved = samples.saveAndFlush(written);
        entities.clear();

        Sample read = samples.findById(saved.getId()).orElseThrow();
        assertNull(read.getAmount());
        assertNull(read.getText());
        assertNull(read.getRaw());
        assertNull(read.getDay());
        assertNull(read.getMoment());
        assertNull(read.getStamp());
        assertNull(read.getInstant());
        assertNull(read.getOffset());
        assertNull(read.getDuration());
        assertNull(read.getYear());
        assertNull(read.getStatus());
        assertNull(read.getPrice());
    }

    /**
     * A stored procedure, called the way an application calls one.
     *
     * <p>{@code SimpleJdbcCall} is what Spring users reach for, and it goes
     * through {@code CallableStatement} - the escape syntax, an {@code OUT}
     * parameter registered before the call and read after it. The four
     * servers need four different {@code create procedure} statements and
     * nothing else: the Java below is the same for all of them, which is the
     * point.
     *
     * <p><b>Nothing is declared here.</b> Spring reads the procedure's
     * parameters from {@code getProcedureColumns} and binds them by the name
     * the server gave them, which is the path most applications take and the
     * one that used to be impossible - all four drivers answered that call
     * with an empty result until the catalog queries behind it were written.
     */
    @Test
    void aStoredProcedureIsCalledThroughSimpleJdbcCall() {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        String product = jdbc.execute((ConnectionCallback<String>) connection ->
                connection.getMetaData().getDatabaseProductName());

        drop(jdbc, product);
        jdbc.execute(createDouble(product));
        try {
            Map<String, Object> answer = new SimpleJdbcCall(jdbc)
                    .withProcedureName("zl_spring_double")
                    .execute(Map.of("n", 21));
            assertEquals(42, doubled(answer).intValue(), "the procedure answered " + answer);
        } finally {
            drop(jdbc, product);
        }
    }

    /**
     * The output, whatever case the server names it in.
     *
     * <p>Oracle stores an unquoted declaration upper case and hands the name
     * back that way, so the key is {@code DOUBLED} there and {@code doubled}
     * on the other three. That is the server's doing, not the driver's, and
     * an application meets it with any driver.
     */
    private static Number doubled(Map<String, Object> answer) {
        for (Map.Entry<String, Object> entry : answer.entrySet()) {
            if (entry.getKey().equalsIgnoreCase("doubled")) {
                return (Number) entry.getValue();
            }
        }
        throw new AssertionError("no output called doubled in " + answer);
    }

    /** One procedure, four dialects - the only part of the test that differs. */
    private static String createDouble(String product) {
        String name = product.toLowerCase(java.util.Locale.ROOT);
        if (name.contains("postgres")) {
            return "create procedure zl_spring_double(in n int, inout doubled int) "
                    + "language plpgsql as $$ begin doubled := n * 2; end $$";
        }
        if (name.contains("mysql") || name.contains("mariadb")) {
            return "create procedure zl_spring_double(in n int, out doubled int) "
                    + "begin set doubled = n * 2; end";
        }
        if (name.contains("microsoft") || name.contains("sql server")) {
            return "create procedure zl_spring_double @n int, @doubled int output as "
                    + "set @doubled = @n * 2";
        }
        if (name.contains("oracle")) {
            return "create or replace procedure zl_spring_double"
                    + "(n in number, doubled out number) as begin doubled := n * 2; end;";
        }
        throw new IllegalStateException("no procedure written for " + product);
    }

    /** Dropping something that may not be there differs per server as well. */
    private static void drop(JdbcTemplate jdbc, String product) {
        String name = product.toLowerCase(java.util.Locale.ROOT);
        try {
            if (name.contains("postgres")) {
                jdbc.execute("drop procedure if exists zl_spring_double(int, int)");
            } else if (name.contains("microsoft") || name.contains("sql server")) {
                jdbc.execute("if object_id('zl_spring_double') is not null "
                        + "drop procedure zl_spring_double");
            } else if (name.contains("oracle")) {
                jdbc.execute("begin execute immediate 'drop procedure zl_spring_double'; "
                        + "exception when others then null; end;");
            } else {
                jdbc.execute("drop procedure if exists zl_spring_double");
            }
        } catch (org.springframework.dao.DataAccessException leftOver) {
            throw new IllegalStateException("could not drop the test procedure", leftOver);
        }
    }
}
