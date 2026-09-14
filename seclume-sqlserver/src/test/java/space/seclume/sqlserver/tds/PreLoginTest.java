package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The PRELOGIN exchange against a <b>real</b> SQL Server.
 *
 * <p>What is checked is the packet layer and the option table: header layout,
 * the big-endian length (the only field in TDS that is not little-endian),
 * reassembly of the answer, and reading the offset/length table.
 *
 * <p>Without a reachable server this is skipped, not failed.
 */
class PreLoginTest {

    private static final String HOST =
            System.getProperty("seclume.mssql.host", "db.example.invalid");
    private static final int PORT = Integer.getInteger("seclume.mssql.port", 1433);

    @BeforeAll
    static void findTheServer() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no SQL Server on " + HOST + ":" + PORT);
        }
    }

    @Test
    void theServerAnswersPreLogin() throws Exception {
        try (TdsChannel channel = TdsChannel.connect(HOST, PORT, 10_000)) {
            PreLogin preLogin = new PreLogin();
            preLogin.exchange(channel, Tds.ENCRYPT_OFF);

            assertTrue(preLogin.serverMajor() > 0,
                    "the server did not report a version");
            System.out.println("PRELOGIN: version=" + preLogin.serverVersion()
                    + ", encryption=" + preLogin.encryption()
                    + " (supported=" + preLogin.supportsEncryption()
                    + ", required=" + preLogin.requiresEncryption() + ")");
        }
    }

    /**
     * If the client asks for encryption the server has to offer it - it has
     * been able to since SQL Server 2005, and since 2022 many setups insist
     * on it.
     */
    @Test
    void theServerOffersEncryption() throws Exception {
        try (TdsChannel channel = TdsChannel.connect(HOST, PORT, 10_000)) {
            PreLogin preLogin = new PreLogin();
            preLogin.exchange(channel, Tds.ENCRYPT_ON);
            assertTrue(preLogin.supportsEncryption(),
                    "the server does not support encryption at all: " + preLogin.encryption());
            System.out.println("with ENCRYPT_ON: " + preLogin.encryption());
        }
    }
}
