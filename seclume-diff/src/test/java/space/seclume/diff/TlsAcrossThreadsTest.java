package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * A connection on seclume's own TLS stack, opened in one thread and used in
 * others - a platform thread, a virtual thread, and back.
 *
 * <p>Every pool does exactly this: the connection is opened by whoever fills
 * the pool and used by whoever borrows it. The record layer kept its AES key
 * in a confined arena, so the first statement from any thread but the opening
 * one failed with {@code WrongThreadException} - on all four databases, and
 * only with {@code tlsStack=seclume}, which is why nothing that ran in one
 * thread ever saw it. Found on 25.09.2026 while handing an encrypted session
 * from one gateway to another.
 */
@Timeout(120)
class TlsAcrossThreadsTest {

    @ParameterizedTest
    @ValueSource(strings = {"PostgreSQL", "MySQL", "SQL Server", "Oracle"})
    void theConnectionWorksFromEveryThread(String database) throws Exception {
        String url = url(database);
        try (Connection connection = DriverManager.getConnection(url)) {
            assertEquals("1", ask(connection, database, 1), database + ", the opening thread");
            try (var platform = Executors.newSingleThreadExecutor()) {
                assertEquals("2", CompletableFuture.supplyAsync(
                        () -> ask(connection, database, 2), platform).get(30, TimeUnit.SECONDS),
                        database + ", another platform thread");
            }
            try (var virtual = Executors.newVirtualThreadPerTaskExecutor()) {
                assertEquals("3", CompletableFuture.supplyAsync(
                        () -> ask(connection, database, 3), virtual).get(30, TimeUnit.SECONDS),
                        database + ", a virtual thread");
            }
            assertEquals("4", ask(connection, database, 4), database + ", the first one again");
        }
    }

    private static String ask(Connection connection, String database, int n) {
        String sql = "select " + n + (database.equals("Oracle") ? " from dual" : "");
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        } catch (Exception e) {
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    private static String url(String database) {
        String host = TestHosts.database();
        return switch (database) {
            case "PostgreSQL" -> with("jdbc:seclume:postgresql://" + host + ":"
                    + Integer.getInteger("seclume.pgtls.port", 5433)
                    + "/seclume_test?user=seclume_test&tls=require", host,
                    Integer.getInteger("seclume.pgtls.port", 5433), ".local-pgtls-password");
            case "MySQL" -> with("jdbc:seclume:mysql://" + host + ":"
                    + Integer.getInteger("seclume.mysql.port", 3307)
                    + "/seclume_test?user=seclume_test&tls=require", host,
                    Integer.getInteger("seclume.mysql.port", 3307), ".local-mysql-password");
            case "SQL Server" -> with("jdbc:seclume:sqlserver://" + host + ":"
                    + Integer.getInteger("seclume.mssql8.port", 1435)
                    + "/master?user=sa&tds=8.0&trustServerCertificate=true", host,
                    Integer.getInteger("seclume.mssql8.port", 1435), ".local-mssql-password");
            default -> with("jdbc:seclume:oracle://" + host + ":"
                    + Integer.getInteger("seclume.oracle.tcps.port", 2484)
                    + "/FREEPDB1?user=seclume_test&tls=require", host,
                    Integer.getInteger("seclume.oracle.tcps.port", 2484),
                    ".local-oracle-password");
        };
    }

    private static String with(String url, String host, int port, String secretFile) {
        Path secret = TypeCatalogTest.locate(secretFile);
        TypeCatalogTest.reachable(host, port, secret);
        return url + "&tlsStack=seclume&provider=file&path=" + TypeCatalogTest.slash(secret);
    }
}
