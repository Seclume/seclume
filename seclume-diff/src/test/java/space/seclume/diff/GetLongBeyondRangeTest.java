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
import java.sql.ResultSet;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.tck.TestHosts;

/**
 * 18446744073709551621 is 2^64 + 5: read with getLong it came back as 5 - a
 * wrong number that looks right. Every driver refuses it as out of range,
 * SQLState 22003, and getBigDecimal still has it whole.
 */
class GetLongBeyondRangeTest {

    private static final String BEYOND = "18446744073709551621";

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
        "postgresql|5432|seclume_test|user=seclume_test&tls=off|.local-pg-password|select cast(" + BEYOND + " as numeric)",
        "mysql|3307|seclume_test|user=seclume_test&tls=off&allowPublicKeyRetrieval=true|.local-mysql-password|select cast(" + BEYOND + " as decimal(30))",
        "sqlserver|1433|master|user=sa&trustServerCertificate=true|.local-mssql-password|select cast(" + BEYOND + " as decimal(30))",
        "oracle|1521|FREEPDB1|user=seclume_test&tls=off|.local-oracle-password|select " + BEYOND + " from dual"})
    void aNumberBeyondALongIsOutOfRange(String driver, int port, String database, String options,
                                        String passwordFile, String query) throws Exception {
        String host = driver.equals("postgresql") ? TestHosts.postgres() : TestHosts.database();
        if (driver.equals("postgresql")) {
            port = TestHosts.postgresPort();
            passwordFile = TestHosts.postgresPasswordFile();
        }
        Path password = null;
        for (Path candidate : new Path[] {Path.of(passwordFile), Path.of("..", passwordFile)}) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no " + passwordFile);
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("no " + driver + " on " + host + ":" + port);
        }
        String url = "jdbc:seclume:" + driver + "://" + host + ":" + port + "/" + database + "?"
                + options + "&provider=file&path=" + password.toString().replace('\\', '/');
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet rows = s.executeQuery(query)) {
            assertTrue(rows.next());
            SQLException refused = assertThrows(SQLException.class, () -> rows.getLong(1));
            assertEquals("22003", refused.getSQLState(), String.valueOf(refused));
            assertTrue(refused instanceof SQLDataException, refused.getClass().getName());
            assertEquals(new java.math.BigDecimal(BEYOND), rows.getBigDecimal(1).stripTrailingZeros());
        }
    }
}
