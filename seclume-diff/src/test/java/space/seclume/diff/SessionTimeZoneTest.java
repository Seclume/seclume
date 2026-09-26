package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.TimeZone;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.tck.TestHosts;

/**
 * The session's time zone is the one the vendor's driver would have set.
 *
 * <p>pgjdbc and ojdbc start the session in the JVM's zone; MySQL and SQL
 * Server drivers leave it to the server. Whatever a session zone decides -
 * {@code ::date} of a {@code timestamptz}, Oracle's {@code TIMESTAMP WITH
 * LOCAL TIME ZONE}, {@code from_unixtime} - then reads the same through both
 * drivers. The instant is fixed, 2024-01-01 23:30 UTC, a date boundary for
 * every zone east of UTC.
 *
 * <p>The JVM zone is switched for the run: a region with daylight saving far
 * from UTC, and a bare {@code GMT+05:00}, which PostgreSQL reads with the sign
 * the other way round.
 */
// Alone: it changes the JVM's default time zone, which every other class reads.
@org.junit.jupiter.api.parallel.Isolated
@Timeout(300)
class SessionTimeZoneTest {

    private static final String HOST = TestHosts.database();

    @ParameterizedTest
    @ValueSource(strings = {"Pacific/Auckland", "GMT+05:00", "UTC"})
    void postgresql(String zone) throws Exception {
        Path secret = TypeCatalogTest.locate(TestHosts.postgresPasswordFile());
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        TypeCatalogTest.reachable(host, port, secret);
        same(zone, secret,
                "jdbc:seclume:postgresql://" + host + ":" + port
                        + "/seclume_test?user=seclume_test&tls=off",
                "jdbc:postgresql://" + host + ":" + port + "/seclume_test", "seclume_test",
                "select to_char(timestamptz '2024-01-01 23:30:00+00', 'YYYY-MM-DD HH24:MI'), "
                        + "(timestamptz '2024-01-01 23:30:00+00')::date::text");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Pacific/Auckland", "GMT+05:00", "UTC"})
    void oracle(String zone) throws Exception {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path secret = TypeCatalogTest.locate(".local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", HOST);
        TypeCatalogTest.reachable(host, port, secret);
        same(zone, secret,
                "jdbc:seclume:oracle://" + host + ":" + port + "/FREEPDB1?user=seclume_test",
                "jdbc:oracle:thin:@//" + host + ":" + port + "/FREEPDB1", "seclume_test",
                "select to_char(cast(timestamp '2024-01-01 23:30:00 +00:00' "
                        + "as timestamp with local time zone), 'YYYY-MM-DD HH24:MI'), "
                        + "to_char(timestamp '2024-01-01 23:30:00 +00:00' at local, "
                        + "'YYYY-MM-DD HH24:MI TZH:TZM') from dual");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Pacific/Auckland", "UTC"})
    void mysql(String zone) throws Exception {
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path secret = TypeCatalogTest.locate(".local-mysql-password");
        String host = System.getProperty("seclume.mysql.host", HOST);
        TypeCatalogTest.reachable(host, port, secret);
        same(zone, secret,
                "jdbc:seclume:mysql://" + host + ":" + port
                        + "/seclume_test?user=seclume_test&tls=off&allowPublicKeyRetrieval=true",
                "jdbc:mysql://" + host + ":" + port
                        + "/seclume_test?allowPublicKeyRetrieval=true&sslMode=DISABLED",
                "seclume_test",
                "select @@session.time_zone, cast(from_unixtime(1704151800) as char)");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Pacific/Auckland", "UTC"})
    void sqlServer(String zone) throws Exception {
        int port = Integer.getInteger("seclume.mssql.port", 1433);
        Path secret = TypeCatalogTest.locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", HOST);
        TypeCatalogTest.reachable(host, port, secret);
        same(zone, secret,
                "jdbc:seclume:sqlserver://" + host + ":" + port
                        + "/master?user=sa&trustServerCertificate=true",
                "jdbc:sqlserver://" + host + ":" + port
                        + ";databaseName=master;encrypt=true;trustServerCertificate=true", "sa",
                "select current_timezone(), convert(varchar(40), "
                        + "todatetimeoffset('2024-01-01 23:30:00', 0), 127)");
    }

    /** Both drivers, connected while the JVM is in {@code zone}, answer alike. */
    private static void same(String zone, Path secret, String ours, String vendorUrl,
                             String user, String sql) throws Exception {
        TimeZone before = TimeZone.getDefault();
        TimeZone.setDefault(TimeZone.getTimeZone(zone));
        try {
            String seclume;
            try (Connection c = DriverManager.getConnection(ours + "&provider=file&path="
                    + TypeCatalogTest.slash(secret))) {
                seclume = row(c, sql);
            }
            Properties vendor = new Properties();
            vendor.setProperty("user", user);
            vendor.setProperty("password", Files.readString(secret).trim());
            String theirs;
            try (Connection c = DriverManager.getConnection(vendorUrl, vendor)) {
                theirs = row(c, sql);
            }
            assertEquals(theirs, seclume, "JVM zone " + zone);
        } finally {
            TimeZone.setDefault(before);
        }
    }

    private static String row(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1) + " | " + rows.getString(2);
        }
    }
}
