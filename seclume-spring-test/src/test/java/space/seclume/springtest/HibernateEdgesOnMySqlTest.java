package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Hibernate's edge mappings against MySql.
 *
 * <p>Nothing is overridden here. If the tests of the base class pass, the
 * driver gives Hibernate what these mappings need -
 * against this server, not in principle.
 */
@SpringBootTest
@ActiveProfiles("mysql")
class HibernateEdgesOnMySqlTest extends HibernateEdgesTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(".local-mysql-password", space.seclume.tck.TestHosts.database(), 3307);
    }
}
