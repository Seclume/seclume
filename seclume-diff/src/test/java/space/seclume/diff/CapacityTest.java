package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.List;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.ServerCapacity;
import space.seclume.tck.TestHosts;

/** What each server says about its connection limit, as the pool will ask it. */
@Timeout(60)
class CapacityTest {

    record Target(String name, String url, String secret, boolean mustKnow) {
        @Override
        public String toString() {
            return name;
        }
    }

    static List<Target> targets() {
        String host = TestHosts.database();
        return List.of(
                new Target("PostgreSQL", "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                        + TestHosts.postgresPort() + "/seclume_test?user=seclume_test&tls=off",
                        TestHosts.postgresPasswordFile(), true),
                new Target("MySQL", "jdbc:seclume:mysql://" + host + ":3307/seclume_test"
                        + "?user=seclume_test&tls=off&allowPublicKeyRetrieval=true",
                        ".local-mysql-password", false),
                new Target("SQL Server", "jdbc:seclume:sqlserver://" + host
                        + ":1433/master?user=sa&trustServerCertificate=true",
                        ".local-mssql-password", true),
                new Target("Oracle", "jdbc:seclume:oracle://" + host
                        + ":1521/FREEPDB1?user=seclume_test", ".local-oracle-password", false));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("targets")
    void theServerSaysWhatItAllowsOrThatItIsNotVisible(Target target) throws Exception {
        Path secret = TypeCatalogTest.locate(target.secret());
        String address = target.url().substring(target.url().indexOf("//") + 2);
        TypeCatalogTest.reachable(address.substring(0, address.indexOf(':')),
                Integer.parseInt(address.substring(address.indexOf(':') + 1,
                        address.indexOf('/'))), secret);
        try (Connection connection = DriverManager.getConnection(target.url()
                + "&provider=file&path=" + TypeCatalogTest.slash(secret))) {
            ServerCapacity.Capacity capacity =
                    connection.unwrap(ServerCapacity.class).capacity();
            System.out.println("  " + target + ": " + capacity);
            assertTrue(capacity.allowed() == -1 || capacity.allowed() > 0, capacity.toString());
            assertTrue(capacity.inUse() == -1 || capacity.inUse() >= 1,
                    "this connection itself is in use: " + capacity);
            if (target.mustKnow()) {
                assertTrue(capacity.known(), target + " should show both: " + capacity);
            }
            assertTrue(connection.isValid(2), "asking broke the connection");
        }
    }
}
