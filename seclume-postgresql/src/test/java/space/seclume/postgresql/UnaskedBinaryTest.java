package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.CallbackSecretProvider;

/**
 * A server that claims binary for a column the driver asked for as text -
 * here a {@code text} column, in a simple query, which is text throughout -
 * had its bytes decoded as whatever the binary reader made of them. A format
 * the driver never asks for is a malformed answer now.
 */
@Timeout(30)
class UnaskedBinaryTest {

    private static void writeInt(OutputStream out, int value) throws IOException {
        out.write(new byte[] {(byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value});
    }

    private static void message(OutputStream out, char tag, byte[] body) throws IOException {
        out.write(tag);
        writeInt(out, 4 + body.length);
        out.write(body);
    }

    @Test
    void aBinaryClaimForATextColumnIsRefused() throws Exception {
        try (ServerSocket listener = new ServerSocket()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            CompletableFuture<Void> served = CompletableFuture.runAsync(() -> {
                try (Socket socket = listener.accept();
                     DataInputStream in = new DataInputStream(socket.getInputStream())) {
                    OutputStream out = socket.getOutputStream();
                    in.readNBytes(in.readInt() - 4);                 // the startup message
                    message(out, 'R', new byte[] {0, 0, 0, 0});      // AuthenticationOk
                    message(out, 'Z', new byte[] {'I'});
                    out.flush();
                    in.readByte();                                   // Query
                    in.readNBytes(in.readInt() - 4);
                    ByteArrayOutputStream row = new ByteArrayOutputStream();
                    row.write(new byte[] {0, 1});                    // one field
                    row.write("v\0".getBytes(StandardCharsets.US_ASCII));
                    row.write(new byte[] {0, 0, 0, 0, 0, 0});        // table, column
                    row.write(new byte[] {0, 0, 0, 25});             // text
                    row.write(new byte[] {(byte) 0xff, (byte) 0xff}); // varlena
                    row.write(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
                    row.write(new byte[] {0, 1});                    // format: binary
                    message(out, 'T', row.toByteArray());
                    out.flush();
                    in.read();
                } catch (IOException gone) {
                    // the client gave up - what it should do
                }
            });
            PgSession.Settings settings = new PgSession.Settings("127.0.0.1",
                    listener.getLocalPort(), "app", "app",
                    new CallbackSecretProvider(64, target -> {
                        byte[] bytes = "decoy-password".getBytes(StandardCharsets.US_ASCII); // seclume-allow: a test password
                        MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                        return bytes.length;
                    }),
                    "seclume-test", 5_000, HostList.of("127.0.0.1", listener.getLocalPort()),
                    ResultLimit.NONE, TlsMode.OFF, space.seclume.internal.jdbc.TlsStack.AUTO,
                    null, false, RequireAuth.of(null));
            try (PgSession session = PgSession.open(settings)) {
                SQLException refused = assertThrows(SQLException.class,
                        () -> session.askOneValue("select 'x'"));
                assertTrue(String.valueOf(refused.getMessage()).contains("never asks for")
                        || String.valueOf(refused.getCause()).contains("never asks for"),
                        String.valueOf(refused));
            }
            served.cancel(true);
        }
    }
}
