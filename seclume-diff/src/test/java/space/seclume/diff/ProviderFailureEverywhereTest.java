package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.tck.TestHosts;

/**
 * A secret provider that fails at the login - its file not there - is an
 * SQLException 08001 with the failure as its cause, in every driver: not an
 * unchecked exception past every pool and retry that catches SQLException.
 * PostgreSQL's own module has the same test.
 */
class ProviderFailureEverywhereTest {

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
        "mysql|3307|seclume_test|user=seclume_test&tls=off&allowPublicKeyRetrieval=true",
        "sqlserver|1433|master|user=sa&trustServerCertificate=true",
        "oracle|1521|FREEPDB1|user=seclume_test&tls=off"})
    void aProviderThatFailsAtTheLoginIsAnSqlException(String driver, int port, String database,
                                                      String options) {
        String host = TestHosts.database();
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            Assumptions.abort("no " + driver + " on " + host + ":" + port);
        }
        String url = "jdbc:seclume:" + driver + "://" + host + ":" + port + "/" + database + "?"
                + options + "&provider=file&path=/no/such/secret-file";
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url).close());
        assertEquals("08001", refused.getSQLState(), String.valueOf(refused));
        assertNotNull(refused.getCause(), "the provider's failure is the cause");
    }
}
