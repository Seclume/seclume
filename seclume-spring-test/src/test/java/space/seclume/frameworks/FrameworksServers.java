package space.seclume.frameworks;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import javax.sql.DataSource;

import org.junit.jupiter.api.Assumptions;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.tck.TestHosts;

/** The four servers, each behind a pool - or the test is skipped and says why. */
final class FrameworksServers {

    private FrameworksServers() {
    }

    static String postgresUrl() {
        return "jdbc:seclume:postgresql://" + reachable(TestHosts.postgres(),
                TestHosts.postgresPort()) + "/seclume_test?user=seclume_test&tls=off"
                + secret(TestHosts.postgresPasswordFile());
    }

    /**
     * A PostgreSQL that can prepare transactions - its own container, since
     * {@code max_prepared_transactions} is 0 by default and changing it means
     * a restart of a server other tests share.
     */
    static String postgresXaUrl() {
        TestHosts.Server xa = TestHosts.server("pgxa", 5437);
        org.junit.jupiter.api.Assumptions.assumeTrue(TestHosts.isConfigured("pgxa"),
                "no seclume.pgxa.host - no PostgreSQL with two-phase commit");
        return "jdbc:seclume:postgresql://" + reachable(xa.host(), xa.port())
                + "/seclume_test?user=seclume_test&tls=off" + secret(".local-pgxa-password");
    }

    static DataSource postgresXa() throws Exception {
        var source = new space.seclume.postgresql.jdbc.SeclumeDataSource();
        source.setUrl(postgresXaUrl());
        return pool(source);
    }

    static String mysqlUrl() {
        return "jdbc:seclume:mysql://" + reachable(TestHosts.database(), 3307)
                + "/seclume_test?user=seclume_test&tls=off&allowPublicKeyRetrieval=true"
                + secret(".local-mysql-password");
    }

    static String sqlServerUrl() {
        return "jdbc:seclume:sqlserver://" + reachable(TestHosts.database(), 1433)
                + "/seclume_spring?user=sa&trustServerCertificate=true"
                + secret(".local-mssql-password");
    }

    static String oracleUrl() {
        return "jdbc:seclume:oracle://" + reachable(TestHosts.database(), 1521)
                + "/FREEPDB1?user=seclume_test" + secret(".local-oracle-password");
    }

    static DataSource postgres() throws Exception {
        var source = new space.seclume.postgresql.jdbc.SeclumeDataSource();
        source.setUrl(postgresUrl());
        return pool(source);
    }

    static DataSource mysql() throws Exception {
        var source = new space.seclume.mysql.jdbc.MyDataSource();
        source.setUrl(mysqlUrl());
        return pool(source);
    }

    static DataSource sqlServer() throws Exception {
        var source = new space.seclume.sqlserver.jdbc.TdsDataSource();
        source.setUrl(sqlServerUrl());
        return pool(source);
    }

    static DataSource oracle() throws Exception {
        var source = new space.seclume.oracle.jdbc.OraDataSource();
        source.setUrl(oracleUrl());
        return pool(source);
    }

    private static final java.util.Map<String, DataSource> SHARED =
            new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * One pool per server for the whole test run - the framework classes are
     * sixteen, the servers four, and each pool opens its connections once.
     */
    static DataSource shared(String server) throws Exception {
        DataSource known = SHARED.get(server);
        if (known != null) {
            return known;
        }
        DataSource made = switch (server) {
            case "postgres" -> postgres();
            case "mysql" -> mysql();
            case "sqlServer" -> sqlServer();
            case "oracle" -> oracle();
            default -> throw new IllegalArgumentException(server);
        };
        SHARED.put(server, made);
        return made;
    }

    private static DataSource pool(DataSource source) {
        return new SeclumePool(source, new PoolSettings());
    }

    private static String reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
        return host + ":" + port;
    }

    private static String secret(String file) {
        for (Path candidate : List.of(Path.of(file), Path.of("..", file))) {
            if (Files.isReadable(candidate)) {
                return "&provider=file&path="
                        + candidate.toAbsolutePath().normalize().toString().replace('\\', '/');
            }
        }
        Assumptions.abort("no " + file);
        return null;
    }
}
