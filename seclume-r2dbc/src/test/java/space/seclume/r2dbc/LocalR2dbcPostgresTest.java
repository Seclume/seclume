package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.R2dbcBadGrammarException;
import io.r2dbc.spi.Result;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import space.seclume.tck.TestHosts;

/**
 * R2DBC over seclume against PostgreSQL: binds by the database's own
 * placeholders, rows as they are asked for, transactions, savepoints, errors
 * as R2DBC's, and a pool underneath that resets what one borrower set.
 */
@Timeout(120)
class LocalR2dbcPostgresTest {

    private static final String HOST = System.getProperty("seclume.pgtls.host", TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.pgtls.port", 5433);
    private static final Duration WAIT = Duration.ofSeconds(30);

    private static ConnectionFactory factory;
    private static String jdbcUrl;

    @BeforeAll
    static void server() throws Exception {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-pgtls-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + HOST + ":" + PORT);
        }
        jdbcUrl = "jdbc:seclume:postgresql://seclume_test@" + HOST + ":" + PORT
                + "/seclume_test?provider=file&path=" + password.toString().replace('\\', '/')
                + "&trustServerCertificate=true";
        factory = ConnectionFactories.get("r2dbc:seclume:postgresql://seclume_test@" + HOST + ":"
                + PORT + "/seclume_test?provider=file&path="
                + password.toString().replace('\\', '/') + "&options=trustServerCertificate%3Dtrue");
        run("drop table if exists zl_r2dbc");
        run("create table zl_r2dbc (id serial primary key, name text, n int)");
    }

    @AfterAll
    static void drop() {
        if (factory != null) {
            run("drop table if exists zl_r2dbc");
        }
    }

    private static void run(String sql) {
        Mono.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement(sql).execute())
                        .concatMap(Result::getRowsUpdated).then(),
                Connection::close).block(WAIT);
    }

    @Test
    void bindsByTheDatabasesOwnPlaceholdersAndReadsRows() {
        List<String> rows = Flux.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement(
                                "select $2::text || '-' || $1::int as label, $1::int as n")
                        .bind(0, 7).bind("$2", "seven").execute())
                        .concatMap(result -> result.map((row, meta) ->
                                row.get("label", String.class) + "/" + row.get(1, Integer.class))),
                Connection::close).collectList().block(WAIT);
        assertEquals(List.of("seven-7/7"), rows);
    }

    @Test
    void updatesCountAndGeneratedKeysComeBack() {
        Long inserted = Mono.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement("insert into zl_r2dbc (name, n) values ($1, $2)")
                                .bind(0, "a").bind(1, 1).add()
                                .bind(0, "b").bind(1, 2).execute())
                        .concatMap(Result::getRowsUpdated).reduce(0L, Long::sum),
                Connection::close).block(WAIT);
        assertEquals(2L, inserted);

        Integer id = Mono.usingWhen(factory.create(),
                c -> Mono.from(c.createStatement("insert into zl_r2dbc (name, n) values ($1, 3)")
                                .bind(0, "c").returnGeneratedValues("id").execute())
                        .flatMap(result -> Mono.from(result.map((row, meta) ->
                                row.get("id", Integer.class)))),
                Connection::close).block(WAIT);
        assertTrue(id != null && id > 0, "no generated id");
    }

    @Test
    void aRollbackLeavesNothingAndASavepointKeepsWhatCameBefore() {
        Long counted = Mono.usingWhen(factory.create(),
                c -> Mono.from(c.beginTransaction())
                        .then(Mono.from(c.createStatement(
                                "insert into zl_r2dbc (name, n) values ('kept', 10)").execute())
                                .flatMap(r -> Mono.from(r.getRowsUpdated())))
                        .then(Mono.from(c.createSavepoint("s1")))
                        .then(Mono.from(c.createStatement(
                                "insert into zl_r2dbc (name, n) values ('undone', 11)").execute())
                                .flatMap(r -> Mono.from(r.getRowsUpdated())))
                        .then(Mono.from(c.rollbackTransactionToSavepoint("s1")))
                        .then(Mono.from(c.commitTransaction()))
                        .then(count(c, "select count(*) from zl_r2dbc where n in (10, 11)")),
                Connection::close).block(WAIT);
        assertEquals(1L, counted);

        Long afterRollback = Mono.usingWhen(factory.create(),
                c -> Mono.from(c.beginTransaction())
                        .then(Mono.from(c.createStatement(
                                "insert into zl_r2dbc (name, n) values ('gone', 20)").execute())
                                .flatMap(r -> Mono.from(r.getRowsUpdated())))
                        .then(Mono.from(c.rollbackTransaction()))
                        .then(count(c, "select count(*) from zl_r2dbc where n = 20")),
                Connection::close).block(WAIT);
        assertEquals(0L, afterRollback);
    }

    private static Mono<Long> count(Connection c, String sql) {
        return Mono.from(c.createStatement(sql).execute())
                .flatMap(r -> Mono.from(r.map((row, meta) -> row.get(0, Long.class))));
    }

    /** Two of a thousand rows, and the rest is never read - and the connection carries on. */
    @Test
    void rowsAreReadAsTheyAreAskedForAndACancelLetsTheConnectionGoOn() {
        List<Long> answers = Flux.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement("select generate_series(1, 1000)::bigint").execute())
                        .concatMap(r -> Flux.from(r.map((row, meta) -> row.get(0, Long.class)))
                                .take(2))
                        .concatWith(count(c, "select 42::bigint")),
                Connection::close).collectList().block(WAIT);
        assertEquals(List.of(1L, 2L, 42L), answers);
    }

    @Test
    void aMistakeArrivesAsR2dbcsException() {
        Exception failure = assertThrows(Exception.class, () -> Mono.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement("selec 1").execute())
                        .concatMap(Result::getRowsUpdated).then(),
                Connection::close).block(WAIT));
        assertInstanceOf(R2dbcBadGrammarException.class, failure.getCause() != null
                && !(failure instanceof R2dbcBadGrammarException) ? failure.getCause() : failure);
    }

    @Test
    void aNullIsBoundAndReadAsNull() {
        String read = Mono.usingWhen(factory.create(),
                c -> Mono.from(c.createStatement("select $1::text as t")
                                .bindNull(0, String.class).execute())
                        .flatMap(r -> Mono.from(r.map((row, meta) ->
                                java.util.Optional.ofNullable(row.get("t", String.class))))),
                Connection::close).block(WAIT).orElse(null);
        assertNull(read);
    }

    /**
     * Over a SeclumePool with a connection ready, the borrow happens on the
     * subscriber's thread - no hop to a virtual thread - and the session is
     * still the one the reset left: what the last borrower set is gone.
     */
    @Test
    void aReadyPooledConnectionIsLentWithoutAHopAndAfterItsReset() throws Exception {
        space.seclume.pool.PoolSettings settings = new space.seclume.pool.PoolSettings();
        settings.setMaximumPoolSize(1);
        settings.setMinimumIdle(0);
        try (space.seclume.pool.SeclumePool pool = new space.seclume.pool.SeclumePool(
                new org.springframework.jdbc.datasource.DriverManagerDataSource(jdbcUrl), settings)) {
            ConnectionFactory pooled = SeclumeConnectionFactory.over(pool, "postgresql");
            Mono.usingWhen(pooled.create(),
                    c -> Flux.from(c.createStatement("set application_name = 'tenant-a'").execute())
                            .concatMap(Result::getRowsUpdated).then(),
                    Connection::close).block(WAIT);

            Thread caller = Thread.currentThread();
            Thread[] lentOn = new Thread[1];
            String name = null;
            for (int attempt = 0; attempt < 50 && lentOn[0] != caller; attempt++) {
                // The reset's answer has to have arrived for a borrow that
                // does not wait; until then the lane takes it, as it should.
                Thread.sleep(20);
                name = Mono.usingWhen(Mono.from(pooled.create()).doOnNext(c -> lentOn[0] = Thread.currentThread()),
                        c -> Flux.from(c.createStatement("show application_name").execute())
                                .concatMap(r -> r.map((row, meta) -> row.get(0, String.class))).next(),
                        Connection::close).block(WAIT);
            }
            assertEquals(caller, lentOn[0], "a ready connection was not lent on the subscriber's thread");
            assertTrue(name == null || !name.equals("tenant-a"), "the last borrower's setting survived: " + name);
        }
    }
}
