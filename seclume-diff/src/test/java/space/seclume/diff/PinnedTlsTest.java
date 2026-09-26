package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.Secured;
import space.seclume.internal.TrustChoice;
import space.seclume.tck.TestHosts;

/**
 * The test servers' certificates belong to no CA the JVM knows - the case
 * that ends in {@code trustServerCertificate=true} everywhere. With the pin
 * of the server's key the connection verifies after all; with another pin it
 * is refused. All four, both TLS stacks.
 */
@Timeout(120)
class PinnedTlsTest {

    /** One server: the URL encrypting without checking, and how to make it check. */
    record Target(String name, String unchecked, String checked, Path secret) {
        @Override
        public String toString() {
            return name;
        }
    }

    static List<Target> targets() {
        String host = TestHosts.database();
        List<Target> all = new ArrayList<>();
        for (String stack : new String[] {"seclume", "jsse"}) {
            all.add(new Target("PostgreSQL, " + stack,
                    "jdbc:seclume:postgresql://" + host + ":5433/seclume_test?user=seclume_test"
                            + "&tls=require&tlsStack=" + stack,
                    "jdbc:seclume:postgresql://" + host + ":5433/seclume_test?user=seclume_test"
                            + "&tls=verify-full&tlsStack=" + stack, secret(".local-pgtls-password")));
            all.add(new Target("MySQL, " + stack,
                    "jdbc:seclume:mysql://" + host + ":3307/seclume_test?user=seclume_test"
                            + "&tls=require&tlsStack=" + stack,
                    "jdbc:seclume:mysql://" + host + ":3307/seclume_test?user=seclume_test"
                            + "&tls=verify-full&tlsStack=" + stack, secret(".local-mysql-password")));
            all.add(new Target("SQL Server, " + stack,
                    "jdbc:seclume:sqlserver://" + host + ":1435/master?user=sa&tds=8.0"
                            + "&trustServerCertificate=true&tlsStack=" + stack,
                    "jdbc:seclume:sqlserver://" + host + ":1435/master?user=sa&tds=8.0"
                            + "&tlsStack=" + stack, secret(".local-mssql-password")));
            all.add(new Target("Oracle, " + stack,
                    "jdbc:seclume:oracle://" + host + ":2484/FREEPDB1?user=seclume_test"
                            + "&tls=require&tlsStack=" + stack,
                    "jdbc:seclume:oracle://" + host + ":2484/FREEPDB1?user=seclume_test"
                            + "&tls=verify-full&tlsStack=" + stack, secret(".local-oracle-password")));
        }
        return all;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("targets")
    void thePinOfTheServersKeyMakesTheCheckedConnectionWork(Target target) throws Exception {
        TypeCatalogTest.reachable(host(target.unchecked()), port(target.unchecked()),
                target.secret());
        String pin;
        try (Connection unchecked = DriverManager.getConnection(target.unchecked() + auth(target))) {
            assertNotNull(Secured.of(unchecked).serverCertificate(),
                    "an encrypted connection shows no certificate");
            pin = TrustChoice.pinOf(Secured.of(unchecked).serverCertificate());
        }
        // Without a pin the checked connection fails - the certificate is its own.
        assertThrows(SQLException.class,
                () -> DriverManager.getConnection(target.checked() + auth(target)).close());
        try (Connection pinned = DriverManager.getConnection(
                target.checked() + "&tlsPin=" + pin + auth(target))) {
            assertTrue(pinned.isValid(5));
        }
        String wrong = "sha256/" + Base64.getEncoder().encodeToString(new byte[32]);
        SQLException refused = assertThrows(SQLException.class, () -> DriverManager
                .getConnection(target.checked() + "&tlsPin=" + wrong + auth(target)).close());
        assertTrue(chain(refused).contains("not the pinned one"), chain(refused));
    }

    private static String auth(Target target) {
        return "&provider=file&path=" + TypeCatalogTest.slash(target.secret());
    }

    private static Path secret(String name) {
        return TypeCatalogTest.locate(name);
    }

    private static String host(String url) {
        String rest = url.substring(url.indexOf("//") + 2);
        return rest.substring(0, rest.indexOf(':'));
    }

    private static int port(String url) {
        String rest = url.substring(url.indexOf("//") + 2);
        return Integer.parseInt(rest.substring(rest.indexOf(':') + 1, rest.indexOf('/')));
    }

    private static String chain(Throwable failure) {
        StringBuilder all = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            all.append(t.getMessage()).append(" <- ");
        }
        return all.toString();
    }
}
