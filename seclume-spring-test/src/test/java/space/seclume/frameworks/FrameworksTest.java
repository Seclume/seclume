package space.seclume.frameworks;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.sql.DataSource;

import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.ExecutorType;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

import liquibase.Scope;
import liquibase.command.CommandScope;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;

/**
 * The frameworks beyond Hibernate and Spring Data JPA - Liquibase, jOOQ,
 * MyBatis and Spring Data JDBC - on all four.
 *
 * <p>Each through its own API and not through Spring Boot's
 * auto-configuration, so that none of them has to share a context with
 * Flyway and JPA, and so that what is under test is the framework talking to
 * the driver rather than the framework's Spring glue. Every one of them reads
 * the driver differently: Liquibase through {@code DatabaseMetaData} and
 * {@code getDatabaseProductName} to pick its dialect, jOOQ through the SQL it
 * renders, MyBatis through generated keys and its batch executor, Spring Data
 * JDBC through its own dialect detection and aggregates that span two tables.
 *
 * <p><b>jOOQ's open-source edition has no SQL Server or Oracle dialect</b> -
 * those are in its commercial editions. There it runs with
 * {@code SQLDialect.DEFAULT}, which is what someone on the free edition gets,
 * and the queries are chosen to be ones that dialect renders portably.
 */
abstract class FrameworksTest {

    /*
     * The cases are here and the @Test methods in one abstract class per
     * framework - LiquibaseCase, JooqCase, MyBatisCase, SpringDataJdbcCase -
     * so that each framework has a test class per server of its own. That is
     * what FrameworkMatrix counts: a class that proves Liquibase on MySQL, not
     * a class that proves four things at once.
     *
     * The package is not under space.seclume.springtest on purpose: the Spring
     * Boot application there scans its package, and would pick up
     * DataJdbcConfiguration below - its DataSourceTransactionManager then
     * replaced JPA's, and every repository update in the Boot tests failed with
     * "no active transaction".
     */

    /** The server, as each subclass reaches it. */
    abstract DataSource dataSource() throws Exception;

    private static final java.util.Map<DataSource, AnnotationConfigApplicationContext> SPRING =
            new java.util.concurrent.ConcurrentHashMap<>();

    private DataSource source;
    private String product;

    @BeforeEach
    void tables() throws Exception {
        source = dataSource();
        try (Connection connection = source.getConnection();
             Statement statement = connection.createStatement()) {
            product = connection.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT);
            boolean fresh = false;
            fresh |= createIfMissing(statement, connection, "fw_item", "create table fw_item (id "
                    + identity() + " primary key, name varchar(80) not null, "
                    + "price decimal(10, 2), created " + timestamp() + ")");
            fresh |= createIfMissing(statement, connection, "dj_order", "create table dj_order (id "
                    + identity() + " primary key, customer varchar(80) not null, version int)");
            fresh |= createIfMissing(statement, connection, "dj_line", "create table dj_line "
                    + "(dj_order " + bigint() + " not null, line_no int not null, "
                    + "product varchar(80) not null, quantity int not null, "
                    + "primary key (dj_order, line_no))");
            for (String table : List.of("dj_line", "dj_order", "fw_item")) {
                statement.execute("delete from " + table);
            }
            if (fresh && product.contains("oracle")) {
                readableReadOnly(connection);
            }
        }
    }

    // ================================================================ Liquibase

    /**
     * Update, rollback, update again - and the history Liquibase keeps.
     *
     * <p>Liquibase picks its dialect from {@code getDatabaseProductName} and
     * reads the schema through {@code DatabaseMetaData}; its lock and history
     * tables are created and queried through the driver like anything else.
     */
    final void checkLiquibaseUpdatesRollsBackAndUpdatesAgain() throws Exception {
        try (Connection connection = source.getConnection();
             Statement statement = connection.createStatement()) {
            // Upper case, as Liquibase creates its own tables - MySQL on Linux
            // tells the two apart, the other three fold unquoted names.
            for (String table : List.of("lb_customer", "DATABASECHANGELOG",
                                        "DATABASECHANGELOGLOCK")) {
                drop(statement, table);
            }
        }
        // Three runs, as three deployments would make them: each with its own
        // connection and its own Liquibase database object.
        assertFalse(liquibase("update", Map.of()).equals("unsupported"),
                "Liquibase did not recognise " + product);
        try (Connection connection = source.getConnection()) {
            assertTrue(hasColumn(connection, "lb_customer", "email"),
                    "the third changeset did not add the column");
            assertEquals(2, count(connection, "lb_customer"));
        }
        liquibase("rollbackCount", Map.of("count", 1));
        try (Connection connection = source.getConnection()) {
            assertFalse(hasColumn(connection, "lb_customer", "email"),
                    "the rollback did not remove the column");
        }
        liquibase("update", Map.of());
        try (Connection connection = source.getConnection()) {
            assertTrue(hasColumn(connection, "lb_customer", "email"));
            assertEquals(3, count(connection, "DATABASECHANGELOG"),
                    "three changesets in the history");
        }
    }

    /** One Liquibase command on a connection of its own; answers the dialect it chose. */
    private String liquibase(String command, Map<String, Object> extra) throws Exception {
        try (Connection connection = source.getConnection()) {
            Database database = DatabaseFactory.getInstance()
                    .findCorrectDatabaseImplementation(new JdbcConnection(connection));
            liquibase(command, database, extra);
            return database.getShortName();
        }
    }

    private static void liquibase(String command, Database database, Map<String, Object> extra)
            throws Exception {
        Scope.child(Map.of(), () -> {
            CommandScope scope = new CommandScope(command)
                    .addArgumentValue("database", database)
                    .addArgumentValue("changelogFile", "frameworks/liquibase/changelog.yaml");
            extra.forEach(scope::addArgumentValue);
            scope.execute();
        });
    }

    // ===================================================================== jOOQ

    final void checkJooqInsertsQueriesBatchesAndRollsBack() {
        DSLContext jooq = DSL.using(source, jooqDialect());
        var item = DSL.table(DSL.unquotedName("fw_item"));
        var name = DSL.field(DSL.unquotedName("name"), String.class);
        var price = DSL.field(DSL.unquotedName("price"), BigDecimal.class);
        var created = DSL.field(DSL.unquotedName("created"), LocalDateTime.class);

        LocalDateTime now = LocalDateTime.of(2026, 9, 23, 12, 30, 15);
        assertEquals(1, jooq.insertInto(item, name, price, created)
                .values("widget", new BigDecimal("9.99"), now).execute());

        // A batch of bound inserts.
        var batch = jooq.batch(jooq.insertInto(item, name, price, created)
                .values((String) null, (BigDecimal) null, (LocalDateTime) null));
        for (int i = 0; i < 20; i++) {
            batch.bind("gadget-" + i, BigDecimal.valueOf(i), now.plusMinutes(i));
        }
        int[] counts = batch.execute();
        assertEquals(20, counts.length);

        // A typed read with a condition, an order and a limit.
        // With a dialect a limit is rendered the server's way; DEFAULT renders
        // LIMIT, which SQL Server and Oracle do not parse - a limit of the free
        // edition, not of the driver - so there the rows are cut here.
        var ordered = jooq.select(name).from(item)
                .where(price.lt(new BigDecimal("5")))
                .orderBy(price.asc());
        List<String> cheapest = jooqDialect() == SQLDialect.DEFAULT
                ? ordered.fetch(name).subList(0, 3)
                : ordered.limit(3).fetch(name);
        assertEquals(List.of("gadget-0", "gadget-1", "gadget-2"), cheapest);

        Record widget = jooq.select(name, price, created).from(item)
                .where(name.eq("widget")).fetchOne();
        assertNotNull(widget);
        assertEquals(0, new BigDecimal("9.99").compareTo(widget.get(price)));
        assertEquals(now, widget.get(created));

        // A transaction that throws is rolled back.
        assertThrows(IllegalStateException.class, () -> jooq.transaction(configuration -> {
            DSL.using(configuration).deleteFrom(item).execute();
            throw new IllegalStateException("roll it back");
        }));
        assertEquals(21, jooq.fetchCount(item));

        // And a lazy cursor over the result.
        try (var cursor = jooq.select(name).from(item).orderBy(name).fetchLazy()) {
            int seen = 0;
            while (cursor.hasNext()) {
                cursor.fetchNext();
                seen++;
            }
            assertEquals(21, seen);
        }
    }

    // ================================================================== MyBatis

    /** A mapper interface - annotations, not XML, so the whole case is in this file. */
    public interface ItemMapper {

        @org.apache.ibatis.annotations.Insert(
                "insert into fw_item (name, price, created) values (#{name}, #{price}, #{created})")
        @org.apache.ibatis.annotations.Options(useGeneratedKeys = true, keyProperty = "id",
                keyColumn = "id")
        int insert(Item item);

        /**
         * The same without keys, for the batch executor: keys from a batch are
         * something Microsoft's own driver does not deliver either, and
         * MyBatis asks for them only when told to.
         */
        @org.apache.ibatis.annotations.Insert(
                "insert into fw_item (name, price, created) values (#{name}, #{price}, #{created})")
        int insertPlain(Item item);

        @org.apache.ibatis.annotations.Select({"<script>",
            "select id, name, price, created from fw_item where name in",
            "<foreach item='n' collection='names' open='(' separator=',' close=')'>#{n}</foreach>",
            "order by id", "</script>"})
        List<Item> findByNames(@org.apache.ibatis.annotations.Param("names") List<String> names);

        @org.apache.ibatis.annotations.Update(
                "update fw_item set price = #{price,jdbcType=DECIMAL} where name = #{name}")
        int setPrice(@org.apache.ibatis.annotations.Param("name") String name,
                     @org.apache.ibatis.annotations.Param("price") BigDecimal price);
    }

    /** The row MyBatis maps to and from. */
    public static final class Item {
        private Long id;
        private String name;
        private BigDecimal price;
        private LocalDateTime created;

        public Item() {
        }

        Item(String name, BigDecimal price, LocalDateTime created) {
            this.name = name;
            this.price = price;
            this.created = created;
        }

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public BigDecimal getPrice() {
            return price;
        }

        public void setPrice(BigDecimal price) {
            this.price = price;
        }

        public LocalDateTime getCreated() {
            return created;
        }

        public void setCreated(LocalDateTime created) {
            this.created = created;
        }
    }

    final void checkMyBatisGeneratedKeysDynamicSqlBatchAndNull() {
        org.apache.ibatis.session.Configuration configuration =
                new org.apache.ibatis.session.Configuration(
                        new Environment("test", new JdbcTransactionFactory(), source));
        configuration.setMapUnderscoreToCamelCase(true);
        configuration.addMapper(ItemMapper.class);
        SqlSessionFactory factory = new SqlSessionFactoryBuilder().build(configuration);
        LocalDateTime now = LocalDateTime.of(2026, 9, 23, 8, 0);

        long first;
        try (SqlSession session = factory.openSession()) {
            ItemMapper mapper = session.getMapper(ItemMapper.class);
            Item a = new Item("alpha", new BigDecimal("1.50"), now);
            Item b = new Item("beta", null, now);        // a null MyBatis types as OTHER
            assertEquals(1, mapper.insert(a));
            assertEquals(1, mapper.insert(b));
            assertNotNull(a.getId(), "no generated key came back");
            assertTrue(b.getId() > a.getId(), a.getId() + " then " + b.getId());
            first = a.getId();
            session.commit();
        }

        // The batch executor: statements pile up and go at flush.
        try (SqlSession session = factory.openSession(ExecutorType.BATCH)) {
            ItemMapper mapper = session.getMapper(ItemMapper.class);
            for (int i = 0; i < 30; i++) {
                mapper.insertPlain(new Item("batch-" + i, BigDecimal.ONE, now));
            }
            session.flushStatements();
            session.commit();
        }

        try (SqlSession session = factory.openSession()) {
            ItemMapper mapper = session.getMapper(ItemMapper.class);
            assertEquals(1, mapper.setPrice("beta", new BigDecimal("2.25")));
            List<Item> found = mapper.findByNames(List.of("alpha", "beta", "batch-7"));
            assertEquals(List.of("alpha", "beta", "batch-7"),
                    found.stream().map(Item::getName).toList());
            assertEquals(first, found.get(0).getId());
            assertEquals(0, new BigDecimal("2.25").compareTo(found.get(1).getPrice()));
            assertEquals(now, found.get(2).getCreated());
            session.commit();
        }
    }

    // ======================================================= Spring Data JDBC

    final void checkSpringDataJdbcSavesAnAggregateAcrossTwoTables() {
        DjOrderRepository orders = spring().getBean(DjOrderRepository.class);

        DjOrder order = new DjOrder(null, "Ada", null, List.of(
                new DjLine("tea", 2), new DjLine("scones", 6)));
        DjOrder saved = orders.save(order);
        assertNotNull(saved.id(), "no key for the aggregate root");
        assertEquals(0, saved.version());

        DjOrder loaded = orders.findById(saved.id()).orElseThrow();
        assertEquals(List.of("tea", "scones"), loaded.lines().stream().map(DjLine::product).toList());

        // An update rewrites the children; the version moves.
        DjOrder changed = orders.save(new DjOrder(loaded.id(), loaded.customer(),
                loaded.version(), List.of(new DjLine("coffee", 1))));
        assertEquals(1, changed.version());
        assertEquals(List.of("coffee"), orders.findById(saved.id()).orElseThrow().lines()
                .stream().map(DjLine::product).toList());

        // The stale copy is refused - optimistic locking through the driver's update count.
        assertThrows(OptimisticLockingFailureException.class, () -> orders.save(loaded));

        // A derived query, and a page in a stable order.
        for (int i = 0; i < 7; i++) {
            orders.save(new DjOrder(null, "customer-" + i, null, List.of()));
        }
        assertEquals(1, orders.findByCustomer("Ada").size());
        Page<DjOrder> page = orders.findAll(PageRequest.of(1, 3, Sort.by("customer")));
        assertEquals(8, page.getTotalElements());
        // "Ada" sorts before "customer-0": page 1 starts at the third customer.
        assertEquals(List.of("customer-2", "customer-3", "customer-4"),
                page.getContent().stream().map(DjOrder::customer).toList());
    }

    private AnnotationConfigApplicationContext spring() {
        return SPRING.computeIfAbsent(source, server -> {
            AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
            context.registerBean(DataSource.class, () -> server);
            context.register(DataJdbcConfiguration.class);
            context.refresh();
            return context;
        });
    }

    // ================================================================ helpers

    private SQLDialect jooqDialect() {
        if (product.contains("postgres")) {
            return SQLDialect.POSTGRES;
        }
        if (product.contains("mysql")) {
            return SQLDialect.MYSQL;
        }
        return SQLDialect.DEFAULT;     // SQL Server, Oracle: commercial editions only
    }

    private String identity() {
        if (product.contains("postgres")) {
            return "bigint generated by default as identity";
        }
        if (product.contains("mysql")) {
            return "bigint auto_increment";
        }
        if (product.contains("microsoft")) {
            return "bigint identity";
        }
        return "number(19) generated by default as identity";
    }

    /**
     * The tables are kept between runs and emptied per case, not recreated.
     *
     * <p>On Oracle a read-only transaction may not read a table whose
     * definition changed within the last few seconds - ORA-01466, because the
     * server maps DDL times to SCNs coarsely - and Spring Data JDBC reads in
     * read-only transactions. ojdbc meets exactly the same; so does any
     * application that reads read-only right after a migration.
     */
    private boolean createIfMissing(Statement statement, Connection connection, String table,
            String ddl) throws Exception {
        if (hasTable(connection, table)) {
            return false;
        }
        statement.execute(ddl);
        return true;
    }

    private static boolean hasTable(Connection connection, String table) throws Exception {
        for (String name : new String[] {table, table.toUpperCase(Locale.ROOT)}) {
            try (ResultSet tables = connection.getMetaData().getTables(
                    connection.getCatalog(), null, name, null)) {
                if (tables.next()) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Waits - bounded - until a read-only transaction can read the new tables. */
    private static void readableReadOnly(Connection connection) throws Exception {
        long until = System.nanoTime() + 15_000_000_000L;
        while (true) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            try (Statement probe = connection.createStatement()) {
                probe.executeQuery("select count(*) from dj_order").close();
                return;
            } catch (java.sql.SQLException tooNew) {
                if (tooNew.getErrorCode() != 1466 || System.nanoTime() > until) {
                    throw tooNew;
                }
                Thread.sleep(500);
            } finally {
                connection.rollback();
                connection.setAutoCommit(true);
                connection.setReadOnly(false);
            }
        }
    }

    private String bigint() {
        return product.contains("oracle") ? "number(19)" : "bigint";
    }

    private String timestamp() {
        return product.contains("microsoft") ? "datetime2"
                : product.contains("mysql") ? "datetime(6)" : "timestamp";
    }

    private void drop(Statement statement, String table) throws Exception {
        if (product.contains("oracle")) {
            statement.execute("begin execute immediate 'drop table " + table
                    + " cascade constraints purge'; exception when others then null; end;");
        } else {
            statement.execute("drop table if exists " + table);
        }
    }

    private static boolean hasColumn(Connection connection, String table, String column)
            throws Exception {
        for (String name : new String[] {table, table.toUpperCase(Locale.ROOT)}) {
            try (ResultSet columns = connection.getMetaData().getColumns(
                    connection.getCatalog(), null, name, null)) {
                while (columns.next()) {
                    if (columns.getString("COLUMN_NAME").equalsIgnoreCase(column)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static int count(Connection connection, String table) throws Exception {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select count(*) from " + table)) {
            rows.next();
            return rows.getInt(1);
        }
    }

    /** Spring Data JDBC's own configuration - no Boot, no JPA beside it. */
    @org.springframework.context.annotation.Configuration
    @org.springframework.data.jdbc.repository.config.EnableJdbcRepositories(
            considerNestedRepositories = true,
            basePackageClasses = FrameworksTest.class)
    static class DataJdbcConfiguration
            extends org.springframework.data.jdbc.repository.config.AbstractJdbcConfiguration {

        /**
         * Unquoted names, as the tables were created. Spring Data JDBC quotes
         * by default, and a quoted lower-case name is a different table on
         * Oracle, which folds the unquoted one to upper case.
         */
        @Override
        public org.springframework.data.jdbc.core.mapping.JdbcMappingContext jdbcMappingContext(
                java.util.Optional<org.springframework.data.relational.core.mapping.NamingStrategy>
                        namingStrategy,
                org.springframework.data.jdbc.core.convert.JdbcCustomConversions conversions,
                org.springframework.data.relational.RelationalManagedTypes types) {
            var context = super.jdbcMappingContext(namingStrategy, conversions, types);
            context.setForceQuote(false);
            return context;
        }

        @org.springframework.context.annotation.Bean
        org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations jdbc(
                DataSource source) {
            return new org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate(source);
        }

        @org.springframework.context.annotation.Bean
        org.springframework.transaction.PlatformTransactionManager transactionManager(
                DataSource source) {
            return new org.springframework.jdbc.datasource.DataSourceTransactionManager(source);
        }
    }

    /** The aggregate root. */
    @org.springframework.data.relational.core.mapping.Table("dj_order")
    record DjOrder(@org.springframework.data.annotation.Id Long id, String customer,
                   @org.springframework.data.annotation.Version Integer version,
                   @org.springframework.data.relational.core.mapping.MappedCollection(
                           idColumn = "dj_order", keyColumn = "line_no") List<DjLine> lines) {
    }

    /** A line of it, in a table of its own. */
    @org.springframework.data.relational.core.mapping.Table("dj_line")
    record DjLine(String product, int quantity) {
    }

    interface DjOrderRepository extends
            org.springframework.data.repository.ListCrudRepository<DjOrder, Long>,
            org.springframework.data.repository.PagingAndSortingRepository<DjOrder, Long> {

        List<DjOrder> findByCustomer(String customer);
    }
}
