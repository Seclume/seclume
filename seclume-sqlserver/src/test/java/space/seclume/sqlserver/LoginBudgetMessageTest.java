package space.seclume.sqlserver;

import java.sql.DriverManager;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.DribblingServer;

/**
 * A server that answers the login a byte at a time, each in good time for the
 * read timeout: the login budget closes the connection. What was reported was
 * the read the close broke; it says now that the login did not finish within
 * its budget, and how that budget is made.
 */
@Timeout(30)
class LoginBudgetMessageTest {

    @Test
    void aLoginPastItsBudgetSaysSo() throws Exception {
        // A pre-login answer announced at 1024 bytes.
        try (DribblingServer server = new DribblingServer(new byte[] {0x04, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00})) {
            String url = "jdbc:seclume:sqlserver://127.0.0.1:PORT/app?user=u&connectTimeout=500&provider=file&path=/nonexistent".replace("PORT", String.valueOf(server.port()));
            long started = System.nanoTime();
            SQLException late = org.junit.jupiter.api.Assertions.assertThrows(SQLException.class,
                    () -> DriverManager.getConnection(url).close());
            DribblingServer.assertBudgetSpent(late, (System.nanoTime() - started) / 1_000_000);
        }
    }
}
