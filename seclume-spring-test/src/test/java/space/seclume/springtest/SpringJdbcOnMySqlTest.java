package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Spring JDBC and its transactions against MySql.
 *
 * <p>Nothing is overridden here. If the tests of the base class pass, Spring
 * JDBC and its transaction managers get what they expect from the driver -
 * against this server, not in principle.
 */
@SpringBootTest
@ActiveProfiles("mysql")
class SpringJdbcOnMySqlTest extends SpringJdbcOnSeclumeTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(".local-mysql-password", space.seclume.tck.TestHosts.database(), 3307);
    }
}
