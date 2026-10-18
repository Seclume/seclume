package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.R2dbcBadGrammarException;
import io.r2dbc.spi.Result;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import space.seclume.tck.TestHosts;

/**
 * The same R2DBC cases against all four databases, each in its own SQL: its
 * placeholders ({@code $1}, {@code ?}, {@code @name}, {@code :name}), its
 * identity column, its way of making a thousand rows. What R2DBC promises
 * does not depend on which database is underneath, and neither may the
 * answer.
 */
@Timeout(180)
class LocalR2dbcFourDatabasesTest {

    private static final Duration WAIT = Duration.ofSeconds(60);

    /** One database: where it is and how it spells things. */
    record Db(String name, String protocol, int port, String database, String user,
              String passwordFile, String extra, String p1, String p2, String identity,
              String drop, String thousand) {

        @Override
        public String toString() {
            return name;
        }

        ConnectionFactory factory() {
            Path password = null;
            for (Path candidate : List.of(Path.of(passwordFile), Path.of("..", passwordFile))) {
                if (Files.exists(candidate)) {
                    password = candidate.toAbsolutePath().normalize();
                }
            }
            Assumptions.assumeTrue(password != null, "no " + passwordFile);
            String host = TestHosts.database();
            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress(host, port), 2000);
            } catch (IOException e) {
                Assumptions.abort("no " + name + " on " + host + ":" + port);
            }
            return ConnectionFactories.get("r2dbc:seclume:" + protocol + "://" + user + "@" + host
                    + ":" + port + "/" + database + "?provider=file&path="
                    + password.toString().replace('\\', '/') + extra);
        }

        String table() {
            return "zl_r2dbc_" + protocol;
        }
    }

    static List<Db> databases() {
        return List.of(
                new Db("PostgreSQL", "postgresql", 5433, "seclume_test", "seclume_test",
                        ".local-pgtls-password", "&options=trustServerCertificate%3Dtrue",
                        "$1", "$2", "id serial primary key, name varchar(40), n int",
                        "drop table if exists %s",
                        "select generate_series(1, 1000)::bigint"),
                new Db("MySQL", "mysql", 3307, "seclume_test", "seclume_test",
                        ".local-mysql-password", "&options=allowPublicKeyRetrieval%3Dtrue",
                        "?", "?", "id int auto_increment primary key, name varchar(40), n int",
                        "drop table if exists %s",
                        "with recursive s(n) as (select 1 union all select n + 1 from s "
                                + "where n < 1000) select n from s"),
                new Db("SQL Server", "sqlserver", 1433, "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true",
                        "@a", "@b", "id int identity primary key, name nvarchar(40), n int",
                        "drop table if exists %s",
                        "select top 1000 row_number() over (order by (select null)) "
                                + "from sys.all_objects a cross join sys.all_objects b"),
                new Db("Oracle", "oracle", 1521, "FREEPDB1", "seclume_test",
                        ".local-oracle-password", "",
                        ":a", ":b",
                        "id number generated always as identity primary key, "
                                + "name varchar2(40), n number(9)",
                        "begin execute immediate 'drop table %s purge'; "
                                + "exception when others then null; end;",
                        "select level from dual connect by level <= 1000"));
    }

    private static void run(ConnectionFactory factory, String sql) {
        Mono.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement(sql).execute())
                        .concatMap(Result::getRowsUpdated).then(),
                Connection::close).block(WAIT);
    }

    private static ConnectionFactory withTable(Db db) {
        ConnectionFactory factory = db.factory();
        run(factory, String.format(db.drop(), db.table()));
        run(factory, "create table " + db.table() + " (" + db.identity() + ")");
        return factory;
    }

    private static Mono<Long> count(Connection c, String sql) {
        return Mono.from(c.createStatement(sql).execute())
                .flatMap(r -> Mono.from(r.map((row, meta) ->
                        row.get(0, Number.class).longValue())));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void rowsGoInByPlaceholderAndComeBack(Db db) {
        ConnectionFactory factory = withTable(db);
        String table = db.table();
        Long inserted = Mono.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement("insert into " + table + " (name, n) values ("
                                + db.p1() + ", " + db.p2() + ")")
                                .bind(0, "a").bind(1, 1).add()
                                .bind(0, "b").bind(1, 2).add()
                                .bind(0, "c").bind(1, 3).execute())
                        .concatMap(Result::getRowsUpdated).reduce(0L, Long::sum),
                Connection::close).block(WAIT);
        assertEquals(3L, inserted);

        List<String> names = Flux.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement("select name, n from " + table + " where n >= "
                                + db.p1() + " order by n").bind(0, 2).execute())
                        .concatMap(r -> r.map((row, meta) ->
                                row.get("name", String.class) + row.get("n", Number.class)
                                        .intValue())),
                Connection::close).collectList().block(WAIT);
        assertEquals(List.of("b2", "c3"), names);
        run(factory, String.format(db.drop(), table));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void theGeneratedKeyComesBack(Db db) {
        ConnectionFactory factory = withTable(db);
        Number id = Mono.usingWhen(factory.create(),
                c -> Mono.from(c.createStatement("insert into " + db.table()
                                + " (name, n) values (" + db.p1() + ", 7)")
                                .bind(0, "keyed").returnGeneratedValues("id").execute())
                        .flatMap(r -> Mono.from(r.map((row, meta) -> row.get(0, Number.class)))),
                Connection::close).block(WAIT);
        assertTrue(id != null && id.longValue() > 0, "no generated id: " + id);
        run(factory, String.format(db.drop(), db.table()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aRollbackUndoesAndASavepointKeepsWhatCameBefore(Db db) {
        ConnectionFactory factory = withTable(db);
        String table = db.table();
        Long kept = Mono.usingWhen(factory.create(),
                c -> Mono.from(c.beginTransaction())
                        .then(Mono.from(c.createStatement("insert into " + table
                                + " (name, n) values ('kept', 10)").execute())
                                .flatMap(r -> Mono.from(r.getRowsUpdated())))
                        .then(Mono.from(c.createSavepoint("s1")))
                        .then(Mono.from(c.createStatement("insert into " + table
                                + " (name, n) values ('undone', 11)").execute())
                                .flatMap(r -> Mono.from(r.getRowsUpdated())))
                        .then(Mono.from(c.rollbackTransactionToSavepoint("s1")))
                        .then(Mono.from(c.commitTransaction()))
                        .then(count(c, "select count(*) from " + table + " where n in (10, 11)")),
                Connection::close).block(WAIT);
        assertEquals(1L, kept);

        Long gone = Mono.usingWhen(factory.create(),
                c -> Mono.from(c.beginTransaction())
                        .then(Mono.from(c.createStatement("insert into " + table
                                + " (name, n) values ('gone', 20)").execute())
                                .flatMap(r -> Mono.from(r.getRowsUpdated())))
                        .then(Mono.from(c.rollbackTransaction()))
                        .then(count(c, "select count(*) from " + table + " where n = 20")),
                Connection::close).block(WAIT);
        assertEquals(0L, gone);
        run(factory, String.format(db.drop(), table));
    }

    /** Two of a thousand rows, the rest never read - and the connection goes on. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void rowsComeAsTheyAreAskedFor(Db db) {
        ConnectionFactory factory = db.factory();
        List<Long> answers = Flux.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement(db.thousand()).execute())
                        .concatMap(r -> Flux.from(r.map((row, meta) ->
                                row.get(0, Number.class).longValue())).take(2))
                        .concatWith(count(c, db.thousand().contains("dual")
                                ? "select 42 from dual" : "select 42")),
                Connection::close).collectList().block(WAIT);
        assertEquals(List.of(1L, 2L, 42L), answers);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aNullIsBoundAndReadAsNull(Db db) {
        ConnectionFactory factory = withTable(db);
        String table = db.table();
        Optional<String> read = Mono.usingWhen(factory.create(),
                c -> Mono.from(c.createStatement("insert into " + table + " (name, n) values ("
                                + db.p1() + ", " + db.p2() + ")")
                                .bindNull(0, String.class).bind(1, 30).execute())
                        .flatMap(r -> Mono.from(r.getRowsUpdated()))
                        .then(Mono.from(c.createStatement("select name from " + table
                                + " where n = 30").execute()))
                        .flatMap(r -> Mono.from(r.map((row, meta) ->
                                Optional.ofNullable(row.get("name", String.class))))),
                Connection::close).block(WAIT);
        assertEquals(Optional.empty(), read);
        run(factory, String.format(db.drop(), table));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aMistakeArrivesAsR2dbcsException(Db db) {
        ConnectionFactory factory = db.factory();
        Exception failure = assertThrows(Exception.class, () -> Mono.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement("selec 1").execute())
                        .concatMap(Result::getRowsUpdated).then(),
                Connection::close).block(WAIT));
        Throwable cause = failure instanceof R2dbcBadGrammarException ? failure : failure.getCause();
        assertInstanceOf(R2dbcBadGrammarException.class, cause, String.valueOf(failure));
    }
}
