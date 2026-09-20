package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/** The entity shapes against this server. Nothing is overridden. */
@SpringBootTest
@ActiveProfiles("oracle")
class EntityShapesOnOracleTest extends EntityShapesTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(".local-oracle-password", "db.example.invalid", 1521);
    }
}
