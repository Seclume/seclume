package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Hibernate's edge mappings against SQL Server - the fourth and last
 * of the drivers, so that "add the dependency and it works" is a claim made
 * about all of them rather than about three.
 *
 * <p>Nothing is overridden here. If the tests of the base class pass, the
 * driver gives Hibernate what these mappings need -
 * against this server, not in principle.
 */
@SpringBootTest
@ActiveProfiles("sqlserver")
class HibernateEdgesOnSqlServerTest extends HibernateEdgesTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(".local-mssql-password", space.seclume.tck.TestHosts.database(), 1433);
    }
}
