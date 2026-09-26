package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.TestHosts;

/** tnsnames.ora, as Oracle installations write it. */
class TnsNamesTest {

    private static final String FILE = """
            # production, two listeners
            ORDERS, ORDERS_ALIAS =
              (DESCRIPTION =
                (ADDRESS_LIST =
                  (ADDRESS = (PROTOCOL = TCP)(HOST = db1.example)(PORT = 1521))
                  (ADDRESS = (PROTOCOL = TCP)(HOST = db2.example)(PORT = 1522))
                )
                (CONNECT_DATA = (SERVICE_NAME = orders.example))
              )

            secure = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db3)(PORT=2484))
                      (CONNECT_DATA=(SERVICE_NAME=SECURE)))
            OLD = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db4)(PORT=1521))(CONNECT_DATA=(SID=ORCL)))
            """;

    @Test
    void aliasesCommentsAndAddressLists() throws SQLException {
        Map<String, String> entries = TnsNames.entries(FILE);
        assertEquals(List.of("ORDERS", "ORDERS_ALIAS", "SECURE", "OLD"),
                List.copyOf(entries.keySet()));
        TnsNames.Target orders = TnsNames.target(entries.get("ORDERS"));
        assertEquals(List.of("db1.example:1521", "db2.example:1522"), orders.hosts());
        assertEquals("orders.example", orders.service());
        assertTrue(TnsNames.target(entries.get("SECURE")).tcps());
        SQLException sid = assertThrows(SQLException.class,
                () -> TnsNames.target(entries.get("OLD")));
        assertTrue(sid.getMessage().contains("SERVICE_NAME"), sid.getMessage());
    }

    @Test
    void aTnsUrlBecomesTheOrdinaryOne(@TempDir Path admin) throws Exception {
        Files.writeString(admin.resolve("tnsnames.ora"), FILE, StandardCharsets.UTF_8);
        String base = OraUrl.PREFIX + "tns:";
        assertEquals(OraUrl.PREFIX + "//db1.example:1521,db2.example:1522/orders.example"
                + "?user=app&tnsAdmin=" + admin,
                TnsNames.resolve(base + "orders_alias?user=app&tnsAdmin=" + admin, null));
        assertEquals(OraUrl.PREFIX + "//db3:2484/SECURE?tnsAdmin=" + admin + "&tls=verify-full",
                TnsNames.resolve(base + "SECURE?tnsAdmin=" + admin, null));
        SQLException missing = assertThrows(SQLException.class,
                () -> TnsNames.resolve(base + "NOPE?tnsAdmin=" + admin, null));
        assertTrue(missing.getMessage().contains("NOPE is not in"), missing.getMessage());
    }

    /** A real login through an alias, against the test server. */
    @Test
    void connectsThroughAnAlias(@TempDir Path admin) throws Exception {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.isReadable(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        String host = TestHosts.database();
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, 1521), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle on " + host);
        }
        Files.writeString(admin.resolve("tnsnames.ora"), "TEST_PDB = (DESCRIPTION=(ADDRESS="
                + "(PROTOCOL=TCP)(HOST=" + host + ")(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=FREEPDB1)))\n",
                StandardCharsets.UTF_8);
        String url = OraUrl.PREFIX + "tns:test_pdb?user=seclume_test&provider=file&path="
                + password.toString().replace('\\', '/') + "&tnsAdmin="
                + admin.toString().replace('\\', '/');
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet rows = s.executeQuery("select sys_context('USERENV', 'SERVICE_NAME') from dual")) {
            rows.next();
            assertEquals("FREEPDB1", rows.getString(1).toUpperCase(java.util.Locale.ROOT));
        }
    }
}
