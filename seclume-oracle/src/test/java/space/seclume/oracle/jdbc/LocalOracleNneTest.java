package space.seclume.oracle.jdbc;

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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.NoSecretInHeap;

/**
 * Oracle Native Network Encryption against a listener that requires it
 * ({@code seclume-oracle/proof/nne.sh}: SQLNET.ENCRYPTION_SERVER and
 * SQLNET.CRYPTO_CHECKSUM_SERVER REQUIRED, AES256, SHA256).
 *
 * <p>The server's own view is asserted - {@code v$session_connect_info}
 * names the encryption and checksum adapters of this session - so a
 * connection that merely logged in proves nothing. Beyond the login: a bind
 * and a result larger than one packet, which are split and each packet
 * sealed on its own; a statement that fails, which the server answers with
 * break and reset markers after which both ends derive the checksum keys
 * anew; and the heap searched for the password.
 *
 * <pre>
 *   seclume.oracle.nne.host=db.example.invalid
 *   seclume.oracle.nne.port=1525
 * </pre>
 * The password of {@code seclume_test} is expected in {@code .local-ora-nne-password}.
 */
@Timeout(180)
@org.junit.jupiter.api.parallel.Isolated
class LocalOracleNneTest {

    private static final String HOST = System.getProperty("seclume.oracle.nne.host",
            space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.nne.port", 1525);
    private static Path password;

    @BeforeAll
    static void findTheListener() {
        for (Path candidate : List.of(Path.of(".local-ora-nne-password"),
                Path.of("..", ".local-ora-nne-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-ora-nne-password");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no Oracle with native encryption on " + HOST + ":" + PORT
                    + " - see seclume-oracle/proof/nne.sh");
        }
    }

    private static String url(String nativeEncryption) {
        return "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/FREEPDB1?user=seclume_test"
                + "&provider=file&path=" + password.toString().replace('\\', '/')
                + (nativeEncryption == null ? "" : "&nativeEncryption=" + nativeEncryption);
    }

    @Test
    void theServerSeesAes256AndSha256AndTheWorkGoesThrough() throws Exception {
        try (Connection c = DriverManager.getConnection(url("required"))) {
            List<String> banners = new ArrayList<>();
            try (Statement s = c.createStatement();
                 ResultSet r = s.executeQuery("select network_service_banner "
                         + "from v$session_connect_info where sid = sys_context('USERENV', 'SID')")) {
                while (r.next()) {
                    banners.add(r.getString(1));
                }
            }
            assertTrue(banners.stream().anyMatch(b -> b.startsWith("AES256 Encryption")),
                    banners.toString());
            assertTrue(banners.stream().anyMatch(b -> b.startsWith("SHA256 Crypto-checksumming")),
                    banners.toString());

            // Larger than a packet both ways: split, and every packet sealed on its own.
            String big = "Zeile mit Umlauten äöü\n".repeat(3_000);
            try (Statement s = c.createStatement()) {
                try {
                    s.execute("drop table nne_big purge");
                } catch (SQLException absent) {
                    // not there yet
                }
                s.execute("create table nne_big (body clob)");
                try (PreparedStatement p = c.prepareStatement("insert into nne_big values (?)")) {
                    p.setString(1, big);
                    assertEquals(1, p.executeUpdate());
                }
                try (ResultSet r = s.executeQuery("select body from nne_big")) {
                    r.next();
                    assertEquals(big, r.getString(1));
                }
                int rows = 0;
                try (ResultSet r = s.executeQuery("select rpad('y', 4000, 'y') "
                        + "from dual connect by level <= 50")) {
                    while (r.next()) {
                        assertEquals(4000, r.getString(1).length());
                        rows++;
                    }
                }
                assertEquals(50, rows);
                s.execute("drop table nne_big purge");
            }

            // A failing statement: break and reset markers, the checksum keys
            // derived anew on both ends - and the connection still speaks.
            for (int i = 0; i < 3; i++) {
                SQLException failed = assertThrows(SQLException.class, () -> {
                    try (Statement s = c.createStatement()) {
                        s.executeQuery("select * from no_such_table_here");
                    }
                });
                assertTrue(failed.getMessage().contains("ORA-00942"), failed.getMessage());
                try (Statement s = c.createStatement();
                     ResultSet r = s.executeQuery("select 40 + " + i + " from dual")) {
                    r.next();
                    assertEquals(40 + i, r.getInt(1));
                }
            }
        }
        NoSecretInHeap.assertAbsent(password);
    }

    /**
     * Without the option, as Oracle's own client does by default: the CONNECT
     * does not offer it, the server's ACCEPT asks for it, and it is negotiated.
     */
    @Test
    void withoutTheOptionTheServersDemandIsMet() throws Exception {
        try (Connection c = DriverManager.getConnection(url(null));
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select count(*) from v$session_connect_info "
                     + "where sid = sys_context('USERENV', 'SID') "
                     + "and network_service_banner like 'AES256%'")) {
            r.next();
            assertEquals(1, r.getInt(1));
        }
    }

    /** Switched off, a server that requires it is refused - before TTC, and saying why. */
    @Test
    void offIsRefusedWithTheReason() {
        SQLException refused = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url("off")).close());
        assertTrue(refused.getMessage().contains("requires Oracle native network encryption"),
                refused.getMessage());
    }

    /**
     * Required against a listener left at Oracle's defaults
     * (ENCRYPTION_SERVER=ACCEPTED): the server agrees when the client insists,
     * so a client can have encryption without anyone touching the server.
     */
    @Test
    void requiredAgainstADefaultListenerEncryptsAnyway() throws Exception {
        Path plain = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                plain = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(plain != null, "no .local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", HOST);
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        String plainUrl = "jdbc:seclume:oracle://" + host + ":" + port + "/FREEPDB1"
                + "?user=seclume_test&provider=file&path=" + plain.toString().replace('\\', '/')
                + "&nativeEncryption=required";
        try (Connection c = DriverManager.getConnection(plainUrl);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select count(*) from v$session_connect_info "
                     + "where sid = sys_context('USERENV', 'SID') "
                     + "and network_service_banner like 'AES256%'")) {
            r.next();
            assertEquals(1, r.getInt(1));
        }
    }

    @Test
    void requestedWorksAsWell() throws Exception {
        try (Connection c = DriverManager.getConnection(url("requested"));
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select count(*) from v$session_connect_info "
                     + "where sid = sys_context('USERENV', 'SID') "
                     + "and network_service_banner like 'AES256%'")) {
            r.next();
            assertEquals(1, r.getInt(1));
        }
    }
}
