package space.seclume.springtest;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/** The entity shapes against this server. Nothing is overridden. */
@SpringBootTest
@ActiveProfiles("postgresql")
class EntityShapesOnPostgresTest extends EntityShapesTest {

    @BeforeAll
    static void findTheServer() {
        Servers.require(".local-pg-password", "127.0.0.1", 5432);
    }
}
