package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Hibernate's edge mappings against Oracle.
 *
 * <p>Nothing is overridden here. If the tests of the base class pass, the
 * driver gives Hibernate what these mappings need -
 * against this server, not in principle.
 */
@SpringBootTest
@ActiveProfiles("oracle")
class HibernateEdgesOnOracleTest extends HibernateEdgesTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(".local-oracle-password", space.seclume.tck.TestHosts.database(), 1521);
    }
}
