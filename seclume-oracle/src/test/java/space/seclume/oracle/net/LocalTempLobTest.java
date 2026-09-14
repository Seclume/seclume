package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;
import space.seclume.oracle.OracleSession;

/**
 * Temporary LOBs on the server, against a <b>real</b> Oracle.
 *
 * <p>The create call is transcribed from a recording rather than reasoned out,
 * so only the server can say whether it is right - and with Oracle a wrong
 * field is not an error message but silence. The check uses the length call,
 * which is already proven: a freshly created LOB has to report zero.
 */
class LocalTempLobTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", "db.example.invalid");
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static String url;

    @BeforeAll
    static void findTheServer() {
        Path password = null;
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
        url = "jdbc:seclume:oracle://" + HOST + ":" + PORT + "/FREEPDB1"
                + "?user=seclume_test&provider=file&path="
                + password.toString().replace(File.separatorChar, '/');
    }

    @Test
    void createsAnEmptyTemporaryClob() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            OracleSession session = connection.unwrap(OracleSession.class);
            try (WireBuffer locator = session.createTemporaryLob(true)) {
                assertTrue(locator.position() > 0, "no locator came back");
                System.err.println("[temp] CLOB locator " + locator.position() + " bytes");
                assertEquals(0, session.lobLength(locator, 0, locator.position()),
                        "a fresh temporary LOB is empty");
            }
        }
    }

    /** Create, write, ask again - the shape a temporary LOB exists for. */
    @Test
    void writesIntoATemporaryClob() throws Exception {
        String text = "hallo temporaeres clob";
        try (Connection connection = DriverManager.getConnection(url)) {
            OracleSession session = connection.unwrap(OracleSession.class);
            try (WireBuffer locator = session.createTemporaryLob(true);
                 WireBuffer data = new WireBuffer(256)) {
                for (int i = 0; i < text.length(); i++) {
                    data.putByte((byte) (text.charAt(i) >> 8));
                    data.putByte((byte) text.charAt(i));
                }
                session.writeLob(locator, 0, locator.position(), 1, data, data.position());
                assertEquals(text.length(), session.lobLength(locator, 0, locator.position()),
                        "the LOB did not take the characters");
            }
        }
    }

    /**
     * Freeing, and the proof that it happened.
     *
     * <p>A freed locator has to be refused afterwards. Without that check the
     * call could do nothing at all and still look successful.
     */
    @Test
    void freesATemporaryLob() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            OracleSession session = connection.unwrap(OracleSession.class);
            WireBuffer locator = session.createTemporaryLob(true);
            try {
                assertEquals(0, session.lobLength(locator, 0, locator.position()));
                session.freeTemporaryLob(locator, 0, locator.position());
                java.sql.SQLException refused = assertThrows(java.sql.SQLException.class,
                        () -> session.lobLength(locator, 0, locator.position()),
                        "a freed locator has to be refused");
                System.err.println("[temp] nach dem Freigeben: " + refused.getMessage());
            } finally {
                locator.close();
            }
        }
    }

    @Test
    void createsAnEmptyTemporaryBlob() throws Exception {
        try (Connection connection = DriverManager.getConnection(url)) {
            OracleSession session = connection.unwrap(OracleSession.class);
            try (WireBuffer locator = session.createTemporaryLob(false)) {
                System.err.println("[temp] BLOB locator " + locator.position() + " bytes");
                assertEquals(0, session.lobLength(locator, 0, locator.position()));
            }
        }
    }
}
