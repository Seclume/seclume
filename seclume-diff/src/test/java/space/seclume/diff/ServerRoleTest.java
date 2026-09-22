package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.tck.TestHosts;

/**
 * Each database answering what it is, on all four.
 *
 * <p>The choosing is tested without a server - see {@code TargetServerTest} in
 * the core, where three fake hosts of known roles say more about the rule than
 * one real primary could. What only a real server can say is whether the
 * <b>question</b> is right: four different statements, one per database, each
 * of which has to work on an ordinary application account and has to be
 * understood by {@code ServerRole.read}.
 *
 * <p>That second half is where this kind of feature usually goes wrong. A
 * probe only a DBA may run does not fail loudly - it answers
 * {@code UNKNOWN}, every server is then acceptable to every target, and the
 * routing quietly stops routing. Oracle is the case in point: the obvious
 * query is {@code select database_role from v$database}, and the test user
 * here cannot read {@code v$database} at all. {@code sys_context} can be read
 * by anyone, which is why it is the one in the driver.
 *
 * <p>There is one server of each kind on this network and all four are
 * primaries, so what is asserted is that each says so. A standby answering
 * "standby" is not provable here and is not claimed.
 */
@Timeout(300)
class ServerRoleTest {

    private record Database(String name, String key, int port, String scheme, String database,
                            String user, String passwordFile, String options) {
    }

    static List<Database> databases() {
        return List.of(
                new Database("PostgreSQL", "pg", 5432, "postgresql", "seclume_test",
                        "seclume_test", ".local-pg-password", "&tls=off"),
                new Database("MySQL", "mysql", 3307, "mysql", "seclume_test", "seclume_test",
                        ".local-mysql-password", "&tls=off&allowPublicKeyRetrieval=true"),
                new Database("SQL Server", "mssql", 1433, "sqlserver", "master", "sa",
                        ".local-mssql-password", "&trustServerCertificate=true"),
                new Database("Oracle", "oracle", 1521, "oracle", "FREEPDB1", "seclume_test",
                        ".local-oracle-password", ""));
    }

    /**
     * Asking for a primary reaches the server; asking for a secondary does
     * not, and says why.
     *
     * <p>Both halves together are the test. "It connected" would also be true
     * of a driver that ignores the option entirely, which is exactly the
     * failure worth catching: an option that is read, parsed and then not
     * used looks like a working feature in every log.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aPrimaryIsFoundAndASecondaryIsNot(Database database) throws Exception {
        String base = urlOf(database);
        Assumptions.assumeTrue(base != null, "no " + database.name() + " here");

        try (Connection connection = DriverManager.getConnection(base + "&targetServerType=any")) {
            assertTrue(connection.isValid(5), "the ordinary connect stopped working");
        }
        try (Connection connection = DriverManager.getConnection(
                base + "&targetServerType=primary")) {
            assertTrue(connection.isValid(5),
                    database.name() + " would not give a connection when asked for a primary");
        }

        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(base + "&targetServerType=secondary").close());
        assertTrue(String.valueOf(refused.getMessage()).contains("is a primary"),
                database.name() + " was asked for a secondary and should have said what it "
                        + "found instead: " + refused.getMessage());
        assertEquals("08004", refused.getSQLState(),
                "a server of the wrong kind is not the same failure as one that is down");
    }

    /** And a spelling nobody defined is refused rather than taken as "any". */
    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void aTypoIsRefused(Database database) {
        String base = urlOf(database);
        Assumptions.assumeTrue(base != null, "no " + database.name() + " here");
        Exception wrong = assertThrows(Exception.class,
                () -> DriverManager.getConnection(base + "&targetServerType=primry").close());
        assertTrue(String.valueOf(wrong.getMessage()).contains("any, primary, secondary"),
                "a typo should be refused with what is allowed, got: " + wrong.getMessage());
    }

    private static String urlOf(Database database) {
        String host = System.getProperty("seclume." + database.key() + ".host",
                TestHosts.database());
        if (host == null) {
            return null;
        }
        int port = Integer.getInteger("seclume." + database.key() + ".port", database.port());
        String named = System.getProperty("seclume." + database.key() + ".passwordFile",
                database.passwordFile());
        Path password = null;
        for (Path candidate : List.of(Path.of(named), Path.of("..", named))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        if (password == null) {
            return null;
        }
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            return null;
        }
        return "jdbc:seclume:" + database.scheme() + "://" + host + ":" + port + "/"
                + database.database() + "?user=" + database.user() + database.options()
                + "&provider=file&path="
                + password.toString().replace(java.io.File.separatorChar, '/');
    }
}
