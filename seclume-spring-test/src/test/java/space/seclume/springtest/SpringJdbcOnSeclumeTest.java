package space.seclume.springtest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.BeanPropertySqlParameterSource;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Spring's own JDBC and its transactions - the parts where driver details
 * decide, and which the Spring Data tests never reach.
 *
 * <p>Two halves. <b>Transactions:</b> {@code REQUIRES_NEW}, {@code NESTED}
 * (savepoints, through {@code DataSourceTransactionManager} - Spring offers
 * none through JPA), {@code readOnly}, isolation levels and a
 * transaction timeout - and for each of them that the connection goes back to
 * the pool the way it came out, because a read-only flag or a serializable
 * isolation that survives into the next borrower is a defect nobody would
 * trace to its cause. <b>JDBC:</b> {@code batchUpdate},
 * {@code NamedParameterJdbcTemplate} with an expanded {@code IN} list and an
 * untyped {@code null}, generated keys through a {@code KeyHolder} and
 * {@code SimpleJdbcInsert}, a script split by {@code ScriptUtils}, the JDBC
 * escapes, and a streamed read.
 *
 * <p>The tables are plain ones no entity maps ({@code V6__jdbc_ledger.sql}),
 * so what is under test is Spring JDBC and the driver, not Hibernate.
 */
abstract class SpringJdbcOnSeclumeTest {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private PlatformTransactionManager jpaTransactions;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entities;

    private JdbcTemplate jdbc;
    private DataSourceTransactionManager transactions;
    private String product;

    @BeforeEach
    void clean() {
        jdbc = new JdbcTemplate(dataSource);
        transactions = new DataSourceTransactionManager(dataSource);
        product = jdbc.execute((ConnectionCallback<String>) connection ->
                connection.getMetaData().getDatabaseProductName())
                .toLowerCase(Locale.ROOT);
        jdbc.update("delete from " + table("sp_ledger"));
        jdbc.update("delete from " + table("sp_ledger_auto"));
    }

    // ============================================================ transactions

    /** The inner transaction commits on its own; the outer one's rollback does not touch it. */
    @Test
    void requiresNewCommitsWhateverTheOuterDoes() {
        TransactionTemplate inner = template(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template(TransactionDefinition.PROPAGATION_REQUIRED).executeWithoutResult(outer -> {
            insert(1, "outer");
            inner.executeWithoutResult(ignored -> insert(2, "inner"));
            outer.setRollbackOnly();
        });
        assertEquals(List.of(2), ids());
    }

    /** {@code NESTED}: a savepoint, and rolling back to it undoes only what came after. */
    @Test
    void nestedRollsBackOnlyItsOwnPart() {
        TransactionTemplate nested = template(TransactionDefinition.PROPAGATION_NESTED);
        template(TransactionDefinition.PROPAGATION_REQUIRED).executeWithoutResult(outer -> {
            insert(1, "before");
            nested.executeWithoutResult(inside -> {
                insert(2, "undone");
                inside.setRollbackOnly();
            });
            insert(3, "after");
        });
        assertEquals(List.of(1, 3), ids());
    }

    /**
     * A statement that fails inside a nested transaction, and the outer one
     * carries on.
     *
     * <p>This is the one PostgreSQL makes hard: a failed statement aborts the
     * whole transaction there, and "current transaction is aborted, commands
     * ignored" follows every statement after it - unless the failure is
     * rolled back to a savepoint. So on PostgreSQL this passes only if the
     * savepoint is real.
     */
    @Test
    void aFailureInsideNestedLeavesTheOuterUsable() {
        TransactionTemplate nested = template(TransactionDefinition.PROPAGATION_NESTED);
        template(TransactionDefinition.PROPAGATION_REQUIRED).executeWithoutResult(outer -> {
            insert(1, "first");
            assertThrows(DataIntegrityViolationException.class,
                    () -> nested.executeWithoutResult(inside -> insert(1, "duplicate")));
            insert(2, "after the failure");
        });
        assertEquals(List.of(1, 2), ids());
    }

    /*
     * NESTED through JpaTransactionManager is not tested, because Spring
     * refuses it before the driver is asked: HibernateJpaDialect offers no
     * savepoints ("JpaDialect does not support savepoints"), with any driver.
     * NESTED is a DataSourceTransactionManager feature, and is tested above.
     */

    /**
     * {@code readOnly}: the flag reaches the connection, the server refuses a
     * write where it has read-only transactions - and the next borrower gets
     * a connection that is not read-only.
     *
     * <p>SQL Server has no read-only transaction to switch to. The driver
     * keeps the flag and says so through {@code isReadOnly()}; the write goes
     * through, and that is asserted rather than skipped, so that the day it
     * changes somebody notices.
     */
    @Test
    void readOnlyReachesTheServerAndDoesNotOutliveTheTransaction() {
        TransactionTemplate readOnly = template(TransactionDefinition.PROPAGATION_REQUIRED);
        readOnly.setReadOnly(true);
        boolean[] refused = {false};
        readOnly.executeWithoutResult(status -> {
            Connection connection = DataSourceUtils.getConnection(dataSource);
            try {
                assertTrue(connection.isReadOnly(), "the flag did not reach the connection");
            } catch (java.sql.SQLException e) {
                throw new AssertionError(e);
            }
            try {
                insert(1, "in a read-only transaction");
            } catch (DataAccessException expected) {
                refused[0] = true;
            }
            status.setRollbackOnly();
        });
        assertEquals(!isSqlServer(), refused[0], product
                + (refused[0] ? " refused" : " accepted") + " a write in a read-only transaction");

        // All of the pool, not just the next one: whichever connection had
        // the transaction has to be back to read-write.
        for (int i = 0; i < 4; i++) {
            jdbc.execute((ConnectionCallback<Void>) connection -> {
                assertFalse(connection.isReadOnly(), "a read-only flag outlived its transaction");
                return null;
            });
        }
        insert(2, "after");
        assertEquals(List.of(2), ids());
    }

    /** {@code @Transactional(readOnly = true)} on JPA sets the connection read-only as well. */
    @Test
    void readOnlyThroughJpaReachesTheConnection() {
        TransactionTemplate readOnly = new TransactionTemplate(jpaTransactions);
        readOnly.setReadOnly(true);
        Boolean inside = readOnly.execute(status -> entities.unwrap(org.hibernate.Session.class)
                .doReturningWork(Connection::isReadOnly));
        assertTrue(inside, "Spring asked for a read-only transaction and the connection is not");
        Boolean after = jdbc.execute((ConnectionCallback<Boolean>) Connection::isReadOnly);
        assertFalse(after, "and it came back to the pool read-only");
    }

    /** An isolation level reaches the server - and is reset for the next borrower. */
    @Test
    void anIsolationLevelReachesTheServerAndIsResetAfterwards() {
        int before = jdbc.execute((ConnectionCallback<Integer>) Connection::getTransactionIsolation);
        for (int level : new int[] {Connection.TRANSACTION_SERIALIZABLE,
                                    Connection.TRANSACTION_READ_COMMITTED}) {
            TransactionTemplate template = template(TransactionDefinition.PROPAGATION_REQUIRED);
            template.setIsolationLevel(level);
            template.executeWithoutResult(status -> {
                insert(level, "isolation " + level);   // the transaction has begun
                int reported = jdbc.execute((ConnectionCallback<Integer>)
                        Connection::getTransactionIsolation);
                assertEquals(level, reported, "the driver's own answer");
                String server = serverIsolation();
                if (server != null) {
                    assertEquals(expectedServerIsolation(level), server,
                            "what " + product + " itself says it is running");
                }
            });
            for (int i = 0; i < 4; i++) {
                assertEquals(before, jdbc.execute((ConnectionCallback<Integer>)
                        Connection::getTransactionIsolation),
                        "an isolation level outlived its transaction");
            }
        }
    }

    /**
     * A transaction timeout cuts a statement short - Spring hands the time
     * that is left to {@code setQueryTimeout} - and the connection is usable
     * afterwards.
     */
    @Test
    void aTransactionTimeoutCutsAStatementShort() {
        TransactionTemplate template = template(TransactionDefinition.PROPAGATION_REQUIRED);
        template.setTimeout(1);
        long began = System.nanoTime();
        assertThrows(DataAccessException.class, () -> template.executeWithoutResult(status ->
                jdbc.execute(sleepFiveSeconds())));
        long millis = (System.nanoTime() - began) / 1_000_000;
        assertTrue(millis < 4_000, "a one-second transaction ran " + millis + " ms");
        insert(1, "after the timeout");
        assertEquals(List.of(1), ids());
    }

    // ==================================================================== JDBC

    /** {@code batchUpdate} in slices, and every row arrives. */
    @Test
    void batchUpdateInSlices() {
        List<Object[]> rows = new ArrayList<>();
        for (int i = 1; i <= 250; i++) {
            rows.add(new Object[] {i, "row " + i, new BigDecimal(i + ".25")});
        }
        int[][] counts = jdbc.batchUpdate(
                "insert into " + table("sp_ledger") + " (id, note, amount) values (?, ?, ?)",
                rows, 100, (statement, row) -> {
                    statement.setInt(1, (Integer) row[0]);
                    statement.setString(2, (String) row[1]);
                    statement.setBigDecimal(3, (BigDecimal) row[2]);
                });
        assertArrayEquals(new int[] {100, 100, 50},
                Stream.of(counts).mapToInt(slice -> slice.length).toArray());
        for (int[] slice : counts) {
            for (int count : slice) {
                assertTrue(count == 1 || count == java.sql.Statement.SUCCESS_NO_INFO,
                        "an update count of " + count);
            }
        }
        assertEquals(250, count());
        assertEquals(new BigDecimal("31437.50"), jdbc.queryForObject(
                "select sum(amount) from " + table("sp_ledger"), BigDecimal.class)
                .setScale(2));

        // And the other form: statements without parameters, in one batch.
        int[] plain = jdbc.batchUpdate(
                "update " + table("sp_ledger") + " set note = 'a' where id = 1",
                "update " + table("sp_ledger") + " set note = 'b' where id between 2 and 11");
        assertEquals(2, plain.length);
        // SQL Server sends a static batch as one request and reports
        // SUCCESS_NO_INFO for its parts; JDBC allows it and Spring accepts it.
        assertTrue(plain[0] == 1 || plain[0] == java.sql.Statement.SUCCESS_NO_INFO,
                "counted " + plain[0]);
        assertTrue(plain[1] == 10 || plain[1] == java.sql.Statement.SUCCESS_NO_INFO,
                "counted " + plain[1]);
    }

    /** Named parameters: an expanded {@code IN} list, a bean, and a {@code null} with no type. */
    @Test
    void namedParametersWithAListABeanAndAnUntypedNull() {
        NamedParameterJdbcTemplate named = new NamedParameterJdbcTemplate(jdbc);
        for (int i = 1; i <= 9; i++) {
            named.update("insert into " + table("sp_ledger") + " (id, note, amount) "
                    + "values (:id, :note, :amount)",
                    new BeanPropertySqlParameterSource(new Entry(i, "n" + i,
                            BigDecimal.valueOf(i))));
        }
        List<Integer> found = named.queryForList("select id from " + table("sp_ledger")
                + " where id in (:ids) order by id",
                Map.of("ids", List.of(3, 5, 7)), Integer.class);
        assertEquals(List.of(3, 5, 7), found);

        // No SQL type given: Spring asks getParameterMetaData or falls back
        // to setNull with a guess, and both have to work.
        MapSqlParameterSource untyped = new MapSqlParameterSource()
                .addValue("id", 10).addValue("note", null).addValue("amount", null);
        named.update("insert into " + table("sp_ledger") + " (id, note, amount) "
                + "values (:id, :note, :amount)", untyped);
        Map<String, Object> row = jdbc.queryForMap("select note, amount from "
                + table("sp_ledger") + " where id = 10");
        assertNull(value(row, "note"));
        assertNull(value(row, "amount"));
    }

    /** A {@code KeyHolder}, and {@code SimpleJdbcInsert} - which reads the table's metadata first. */
    @Test
    void generatedKeysThroughAKeyHolderAndSimpleJdbcInsert() {
        KeyHolder first = new GeneratedKeyHolder();
        KeyHolder second = new GeneratedKeyHolder();
        for (KeyHolder holder : List.of(first, second)) {
            jdbc.update(connection -> {
                PreparedStatement statement = connection.prepareStatement("insert into "
                        + table("sp_ledger_auto") + " (note) values (?)", new String[] {"id"});
                statement.setString(1, "keyed");
                return statement;
            }, holder);
        }
        long a = first.getKey().longValue();
        long b = second.getKey().longValue();
        assertTrue(a > 0 && b > a, "keys " + a + ", " + b);

        SimpleJdbcInsert insert = new SimpleJdbcInsert(jdbc)
                .withTableName("sp_ledger_auto")
                .usingGeneratedKeyColumns("id");
        if (isPostgres()) {
            insert.withSchemaName("seclume_spring");
        }
        long c = insert.executeAndReturnKey(Map.of("note", "simple")).longValue();
        assertTrue(c > b, "the key from SimpleJdbcInsert: " + c);
        assertEquals("simple", jdbc.queryForObject("select note from " + table("sp_ledger_auto")
                + " where id = ?", String.class, c));
    }

    /**
     * A script, split the way {@code ScriptUtils} splits it - which is what
     * {@code spring.sql.init}, {@code @Sql} and {@code ResourceDatabasePopulator}
     * all go through: comments of both kinds, a statement over several lines,
     * and a semicolon inside a string literal that must not end it.
     */
    @Test
    void aScriptIsSplitAndRun() {
        String script = """
                -- a line comment; with a semicolon in it
                insert into %1$s (id, note) values (1, 'one; still one');
                /* a block comment;
                   over two lines */
                insert into %1$s (id, note)
                    values (2, 'two');

                update %1$s set note = note || '!' where id = 2;
                """.formatted(table("sp_ledger"));
        if (isSqlServer() || isMySql()) {
            // Neither has || for strings (MySQL only under PIPES_AS_CONCAT).
            script = script.replace("note || '!'", "concat(note, '!')");
        }
        new ResourceDatabasePopulator(new ByteArrayResource(
                script.getBytes(StandardCharsets.UTF_8))).execute(dataSource);
        assertEquals(List.of("one; still one", "two!"), jdbc.queryForList(
                "select note from " + table("sp_ledger") + " order by id", String.class));
    }

    /** The JDBC escapes, sent through JdbcTemplate as a framework would. */
    @Test
    void jdbcEscapesWork() {
        jdbc.update("insert into " + table("sp_ledger") + " (id, note, created) values "
                + "(1, {fn ucase('abc')}, {ts '2026-09-23 10:15:30'})");
        jdbc.update("insert into " + table("sp_ledger") + " (id, note, created) values "
                + "(2, 'a_b', {d '2026-09-24'})");
        assertEquals("ABC!", jdbc.queryForObject("select {fn concat(note, '!')} from "
                + table("sp_ledger") + " where id = 1", String.class));
        assertEquals(LocalDateTime.of(2026, 9, 23, 10, 15, 30), jdbc.queryForObject(
                "select created from " + table("sp_ledger") + " where id = 1",
                Timestamp.class).toLocalDateTime());
        assertEquals(LocalDate.of(2026, 9, 24), jdbc.queryForObject(
                "select created from " + table("sp_ledger") + " where id = 2",
                Timestamp.class).toLocalDateTime().toLocalDate());
        assertEquals(List.of(2), jdbc.queryForList("select id from " + table("sp_ledger")
                + " where note like 'a!_b' {escape '!'}", Integer.class));
    }

    /** {@code queryForStream} with a fetch size - rows arrive in order and all of them. */
    @Test
    void aStreamedReadWithAFetchSize() {
        List<Object[]> rows = new ArrayList<>();
        for (int i = 1; i <= 250; i++) {
            rows.add(new Object[] {i, "s" + i});
        }
        jdbc.batchUpdate("insert into " + table("sp_ledger") + " (id, note) values (?, ?)",
                rows);
        JdbcTemplate streaming = new JdbcTemplate(dataSource);
        streaming.setFetchSize(50);
        List<Integer> seen;
        try (Stream<Integer> stream = streaming.queryForStream(
                "select id from " + table("sp_ledger") + " order by id",
                (result, number) -> result.getInt(1))) {
            seen = stream.collect(Collectors.toList());
        }
        assertEquals(250, seen.size());
        assertEquals(1, seen.get(0));
        assertEquals(250, seen.get(249));
    }

    // ================================================================ helpers

    /** A bean for {@link BeanPropertySqlParameterSource}. */
    public static final class Entry {
        private final int id;
        private final String note;
        private final BigDecimal amount;

        Entry(int id, String note, BigDecimal amount) {
            this.id = id;
            this.note = note;
            this.amount = amount;
        }

        public int getId() {
            return id;
        }

        public String getNote() {
            return note;
        }

        public BigDecimal getAmount() {
            return amount;
        }
    }

    private TransactionTemplate template(int propagation) {
        TransactionTemplate template = new TransactionTemplate(transactions);
        template.setPropagationBehavior(propagation);
        return template;
    }

    private void insert(int id, String note) {
        jdbc.update("insert into " + table("sp_ledger") + " (id, note) values (?, ?)", id, note);
    }

    private List<Integer> ids() {
        return jdbc.queryForList("select id from " + table("sp_ledger") + " order by id",
                Integer.class);
    }

    private int count() {
        return jdbc.queryForObject("select count(*) from " + table("sp_ledger"), Integer.class);
    }

    /** PostgreSQL keeps these in the schema Flyway created; the others in the default one. */
    private String table(String name) {
        return isPostgres() ? "seclume_spring." + name : name;
    }

    private static Object value(Map<String, Object> row, String column) {
        for (Map.Entry<String, Object> entry : row.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(column)) {
                return entry.getValue();
            }
        }
        throw new AssertionError("no column " + column + " in " + row);
    }

    private boolean isPostgres() {
        return product.contains("postgres");
    }

    private boolean isMySql() {
        return product.contains("mysql") || product.contains("mariadb");
    }

    private boolean isSqlServer() {
        return product.contains("microsoft") || product.contains("sql server");
    }

    private boolean isOracle() {
        return product.contains("oracle");
    }

    /** What the server says the running transaction's isolation is, or null where it cannot be asked. */
    private String serverIsolation() {
        if (isPostgres()) {
            return jdbc.queryForObject("show transaction_isolation", String.class);
        }
        if (isMySql()) {
            return jdbc.queryForObject("select @@transaction_isolation", String.class);
        }
        if (isSqlServer()) {
            return String.valueOf(jdbc.queryForObject("select transaction_isolation_level "
                    + "from sys.dm_exec_sessions where session_id = @@spid", Integer.class));
        }
        return null;     // Oracle: only through v$ views an application account cannot read
    }

    private String expectedServerIsolation(int level) {
        boolean serializable = level == Connection.TRANSACTION_SERIALIZABLE;
        if (isPostgres()) {
            return serializable ? "serializable" : "read committed";
        }
        if (isMySql()) {
            return serializable ? "SERIALIZABLE" : "READ-COMMITTED";
        }
        return serializable ? "4" : "2";
    }

    private String sleepFiveSeconds() {
        if (isPostgres()) {
            return "select pg_sleep(5)";
        }
        if (isMySql()) {
            return "select sleep(5)";
        }
        if (isSqlServer()) {
            return "waitfor delay '00:00:05'";
        }
        // Not dbms_session.sleep: the server finishes a PL/SQL sleep before
        // it acts on a break - with Oracle's own thin driver as well, see
        // LocalCancelTest. A long query it stops at once.
        return "select count(*) from all_objects a, all_objects b, all_objects c "
                + "where a.object_id + b.object_id + c.object_id > 0";
    }
}
