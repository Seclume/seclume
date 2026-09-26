package space.seclume.quarkus.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.agroal.api.AgroalDataSource;
import io.quarkus.test.QuarkusExtensionTest;
import space.seclume.tck.TestHosts;

/**
 * One Quarkus application with four datasources, one per seclume kind: Agroal
 * pools seclume connections to PostgreSQL, MySQL, SQL Server and Oracle, each
 * password comes from a file through the URL, and afterwards the
 * application's heap holds none of the four.
 */
class DatasourceTest {

    private static final Path PG = file(TestHosts.postgresPasswordFile());
    private static final Path MYSQL = file(".local-mysql-password");
    private static final Path MSSQL = file(".local-mssql-password");
    private static final Path ORACLE = file(".local-oracle-password");
    private static final String HOST = TestHosts.database();

    @RegisterExtension
    static final QuarkusExtensionTest APP = new QuarkusExtensionTest()
            .overrideConfigKey("quarkus.datasource.devservices.enabled", "false")
            .overrideConfigKey("quarkus.datasource.\"pg\".db-kind", "seclume-postgresql")
            .overrideConfigKey("quarkus.datasource.\"pg\".jdbc.url",
                    "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                    + TestHosts.postgresPort() + "/seclume_test?user=seclume_test&tls=off"
                    + secret(PG))
            .overrideConfigKey("quarkus.datasource.\"mysql\".db-kind", "seclume-mysql")
            .overrideConfigKey("quarkus.datasource.\"mysql\".jdbc.url",
                    "jdbc:seclume:mysql://" + HOST + ":3307/seclume_test?user=seclume_test"
                    + "&tls=off&allowPublicKeyRetrieval=true" + secret(MYSQL))
            .overrideConfigKey("quarkus.datasource.\"mssql\".db-kind", "seclume-sqlserver")
            .overrideConfigKey("quarkus.datasource.\"mssql\".jdbc.url",
                    "jdbc:seclume:sqlserver://" + HOST + ":1433/master?user=sa"
                    + "&trustServerCertificate=true" + secret(MSSQL))
            .overrideConfigKey("quarkus.datasource.\"oracle\".db-kind", "seclume-oracle")
            .overrideConfigKey("quarkus.datasource.\"oracle\".jdbc.url",
                    "jdbc:seclume:oracle://" + HOST + ":1521/FREEPDB1?user=seclume_test"
                    + secret(ORACLE));

    @Inject
    @io.quarkus.agroal.DataSource("pg")
    AgroalDataSource pg;

    @Inject
    @io.quarkus.agroal.DataSource("mysql")
    AgroalDataSource mysql;

    @Inject
    @io.quarkus.agroal.DataSource("mssql")
    AgroalDataSource mssql;

    @Inject
    @io.quarkus.agroal.DataSource("oracle")
    AgroalDataSource oracle;

    private static Path file(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name),
                Path.of("..", "..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static String secret(Path file) {
        return "&provider=file&path=" + (file == null ? "missing"
                : file.toString().replace(java.io.File.separatorChar, '/'));
    }

    private static void need(Path password, String host, int port) {
        Assumptions.assumeTrue(password != null, "no password file for " + host + ":" + port);
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no server on " + host + ":" + port);
        }
    }

    private static void loginAndAsk(AgroalDataSource source, String query, String expected,
                                    String method) throws Exception {
        try (Connection connection = source.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(query)) {
            rows.next();
            assertEquals(expected, rows.getString(1).toLowerCase(java.util.Locale.ROOT));
            String used = space.seclume.Secured.of(connection).authenticationMethod();
            assertNotNull(used);
            if (method != null) {
                assertEquals(method, used);
            }
        }
    }

    @Test
    void postgresql() throws Exception {
        need(PG, TestHosts.postgres(), TestHosts.postgresPort());
        loginAndAsk(pg, "select current_user", "seclume_test", "scram-sha-256");
    }

    @Test
    void mysql() throws Exception {
        need(MYSQL, HOST, 3307);
        loginAndAsk(mysql, "select substring_index(current_user(), '@', 1)", "seclume_test",
                null);
    }

    @Test
    void sqlServer() throws Exception {
        need(MSSQL, HOST, 1433);
        loginAndAsk(mssql, "select suser_sname()", "sa", null);
    }

    @Test
    void oracle() throws Exception {
        need(ORACLE, HOST, 1521);
        loginAndAsk(oracle, "select user from dual", "seclume_test", null);
    }

    /** All four logged in (as far as their servers are there), then one heap search per password. */
    @Test
    void theApplicationsHeapHoldsNoneOfThePasswords() throws Exception {
        int checked = 0;
        for (Object[] each : new Object[][] {
                {PG, pg, TestHosts.postgres(), TestHosts.postgresPort()},
                {MYSQL, mysql, HOST, 3307}, {MSSQL, mssql, HOST, 1433},
                {ORACLE, oracle, HOST, 1521}}) {
            Path password = (Path) each[0];
            if (password == null || !reachable((String) each[2], (int) each[3])) {
                continue;
            }
            try (Connection connection = ((AgroalDataSource) each[1]).getConnection()) {
                connection.isValid(5);
            }
            space.seclume.tck.NoSecretInHeap.assertAbsent(password);
            checked++;
        }
        Assumptions.assumeTrue(checked > 0, "no database reachable");
    }

    private static boolean reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
            return true;
        } catch (IOException unreachable) {
            return false;
        }
    }
}
