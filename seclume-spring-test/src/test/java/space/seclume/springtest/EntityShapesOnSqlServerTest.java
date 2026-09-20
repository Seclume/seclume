package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/** The entity shapes against this server. Nothing is overridden. */
@SpringBootTest
@ActiveProfiles("sqlserver")
class EntityShapesOnSqlServerTest extends EntityShapesTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(".local-mssql-password", space.seclume.tck.TestHosts.database(), 1433);
    }
}
