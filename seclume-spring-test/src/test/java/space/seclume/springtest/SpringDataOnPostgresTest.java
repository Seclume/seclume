package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * The same Spring Data application against Postgres.
 *
 * <p>Nothing is overridden here. If the tests of the base class pass, the
 * driver's JDBC surface is good enough for Hibernate, Spring Data and Flyway -
 * against this server, not in principle.
 */
@SpringBootTest
@ActiveProfiles("postgresql")
class SpringDataOnPostgresTest extends SpringDataOnSeclumeTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(".local-pg-password", "127.0.0.1", 5432);
    }
}
