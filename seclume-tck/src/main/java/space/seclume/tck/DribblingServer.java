package space.seclume.tck;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;

/**
 * A server that answers a login a byte at a time: first {@code prefix} - a
 * packet header announcing more than it will send - then a zero every 150 ms,
 * each in good time for any read timeout. Only a budget for the login as a
 * whole ends it. What the client sends is read and dropped.
 */
public final class DribblingServer implements AutoCloseable {

    private final ServerSocket listener;

    public DribblingServer(byte[] prefix) throws IOException {
        listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            try (Socket client = listener.accept()) {
                InputStream in = client.getInputStream();
                Thread.ofVirtual().start(() -> {
                    try {
                        in.transferTo(OutputStream.nullOutputStream());
                    } catch (IOException gone) {
                        // the client went
                    }
                });
                OutputStream out = client.getOutputStream();
                out.write(prefix);
                out.flush();
                for (int i = 0; i < 400; i++) {
                    out.write(0);
                    out.flush();
                    Thread.sleep(150);
                }
            } catch (IOException | InterruptedException gone) {
                // closed by the budget - what a test wants
            }
        });
    }

    public int port() {
        return listener.getLocalPort();
    }

    /**
     * Checks what a login with a connect timeout of 500 ms reported: that it
     * did not finish within its budget (3 x 500 ms, rounded up to 2 s), as a
     * transient 08001, and soon.
     */
    public static void assertBudgetSpent(SQLException late, long tookMillis) {
        if (!(late instanceof SQLTransientConnectionException)
                || !"08001".equals(late.getSQLState())
                || late.getMessage() == null
                || !late.getMessage().contains("did not finish within its budget of 2 s")
                || !late.getMessage().contains("seclume.loginBudgetFactor 3")) {
            throw new AssertionError("not reported as a spent login budget: " + late, late);
        }
        if (tookMillis >= 10_000) {
            throw new AssertionError("the login was held for " + tookMillis + " ms");
        }
    }

    @Override
    public void close() throws IOException {
        listener.close();
    }
}
