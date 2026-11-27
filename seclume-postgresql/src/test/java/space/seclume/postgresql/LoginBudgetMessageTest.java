package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.CallbackSecretProvider;

/**
 * A server that answers the startup a byte at a time, each in good time for
 * the read timeout: the login budget closes the connection. What was
 * reported was the read the close broke - "the connection failed during
 * startup: ...". It says now that the login did not finish within its budget,
 * and how that budget is made.
 */
@Timeout(30)
class LoginBudgetMessageTest {

    @Test
    void aLoginPastItsBudgetSaysSo() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread.ofVirtual().start(() -> {
                try (Socket client = listener.accept()) {
                    DataInputStream in = new DataInputStream(client.getInputStream());
                    int length = in.readInt();
                    in.skipNBytes(length - 4);
                    OutputStream out = client.getOutputStream();
                    // An authentication request announced at 1000 bytes ...
                    out.write(new byte[] {'R', 0, 0, 0x03, (byte) 0xe8});
                    out.flush();
                    // ... and then sent a byte every 150 ms.
                    for (int i = 0; i < 400; i++) {
                        out.write(0);
                        out.flush();
                        Thread.sleep(150);
                    }
                } catch (IOException | InterruptedException clientGone) {
                    // closed by the budget - what the test wants
                }
            });
            int port = listener.getLocalPort();
            PgSession.Settings settings = new PgSession.Settings("127.0.0.1", port, "app", "app",
                    new CallbackSecretProvider(16, target -> {
                        MemorySegment.copy("x".getBytes(StandardCharsets.US_ASCII), 0, target,
                                ValueLayout.JAVA_BYTE, 0, 1);
                        return 1;
                    }), "seclume-test", 500, HostList.of("127.0.0.1", port), ResultLimit.NONE,
                    TlsMode.OFF);
            long started = System.nanoTime();
            SQLException late = assertThrows(SQLException.class, () -> PgSession.open(settings));
            long took = (System.nanoTime() - started) / 1_000_000;
            assertTrue(late instanceof SQLTransientConnectionException, late.toString());
            assertEquals("08001", late.getSQLState());
            assertTrue(late.getMessage().contains("did not finish within its budget of 2 s")
                    && late.getMessage().contains("seclume.loginBudgetFactor 3"),
                    late.getMessage());
            assertTrue(took < 10_000, "the login was held for " + took + " ms");
        }
    }
}
