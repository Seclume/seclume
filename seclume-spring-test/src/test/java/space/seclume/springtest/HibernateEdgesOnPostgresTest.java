package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Hibernate's edge mappings against Postgres.
 *
 * <p>Nothing is overridden here. If the tests of the base class pass, the
 * driver gives Hibernate what these mappings need -
 * against this server, not in principle.
 */
@SpringBootTest
@ActiveProfiles("postgresql")
class HibernateEdgesOnPostgresTest extends HibernateEdgesTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(space.seclume.tck.TestHosts.postgresPasswordFile(),
                space.seclume.tck.TestHosts.postgres(),
                space.seclume.tck.TestHosts.postgresPort());
    }
}
