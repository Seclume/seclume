package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import space.seclume.r2dbc.SeclumeConnectionFactory;
import space.seclume.tck.TestHosts;

/**
 * The {@code ConnectionFactory} a reactive application gets: over the seclume
 * pool, and so with its reset - what one borrower set in its session, the
 * next one does not find.
 */
class R2dbcAutoConfigurationTest {

    private static final Duration WAIT = Duration.ofSeconds(30);
    private static Path passwordFile;

    @BeforeAll
    static void findTheServer() {
        for (Path candidate : List.of(Path.of(TestHosts.postgresPasswordFile()),
                Path.of("..", TestHosts.postgresPasswordFile()))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null,
                TestHosts.postgresPasswordFile() + " is not there");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TestHosts.postgres(), TestHosts.postgresPort()),
                    1000);
        } catch (IOException e) {
            Assumptions.abort("no PostgreSQL on " + TestHosts.postgres() + ":"
                    + TestHosts.postgresPort());
        }
    }

    private static AnnotationConfigApplicationContext context() {
        Map<String, Object> properties = new LinkedHashMap<>();
        String prefix = "seclume.datasources.main";
        properties.put(prefix + ".url", "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/seclume_test");
        properties.put(prefix + ".username", "seclume_test");
        properties.put(prefix + ".secret.provider", "file");
        properties.put(prefix + ".secret.path", passwordFile.toString().replace('\\', '/'));
        // One connection: the second borrower gets the first one's.
        properties.put(prefix + ".pool.maximum-pool-size", "1");
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        context.register(SeclumeAutoConfiguration.class, SeclumeR2dbcAutoConfiguration.class);
        context.refresh();
        return context;
    }

    private static String one(ConnectionFactory factory, String... sql) {
        return Mono.usingWhen(factory.create(), c -> {
            Mono<String> last = Mono.empty();
            for (String each : sql) {
                last = last.then(Flux.from(c.createStatement(each).execute())
                        .concatMap(r -> r.map((row, meta) -> String.valueOf(row.get(0))))
                        .last(""));
            }
            return last;
        }, Connection::close).block(WAIT);
    }

    @Test
    void theConnectionFactoryBorrowsFromThePoolAndTheNextBorrowerFindsNothingLeft() {
        try (AnnotationConfigApplicationContext context = context()) {
            ConnectionFactory factory = context.getBean(ConnectionFactory.class);
            assertInstanceOf(SeclumeConnectionFactory.class, factory);

            String pid = one(factory,
                    "set statement_timeout = '123s'",
                    "create temporary table zl_r2dbc_left (x int)",
                    "select pg_backend_pid()");
            String[] next = one(factory,
                    "select pg_backend_pid() || '/' || current_setting('statement_timeout') "
                            + "|| '/' || (to_regclass('pg_temp.zl_r2dbc_left') is null)")
                    .split("/");
            assertEquals(pid, next[0], "not the same connection - the test proves nothing");
            assertFalse("2min 3s".equals(next[1]) || "123s".equals(next[1]),
                    "the setting of the borrower before: " + next[1]);
            assertTrue(Boolean.parseBoolean(next[2]) || "t".equals(next[2]),
                    "the temporary table of the borrower before is still there");
        }
    }

    @Test
    void thePlaceholdersAreTheDatabasesOwn() {
        try (AnnotationConfigApplicationContext context = context()) {
            ConnectionFactory factory = context.getBean(ConnectionFactory.class);
            String answer = Mono.usingWhen(factory.create(),
                    c -> Mono.from(c.createStatement("select $1::int + 1").bind(0, 41).execute())
                            .flatMap(r -> Mono.from(r.map((row, meta) ->
                                    String.valueOf(row.get(0))))),
                    Connection::close).block(WAIT);
            assertEquals("42", answer);
        }
    }
}
