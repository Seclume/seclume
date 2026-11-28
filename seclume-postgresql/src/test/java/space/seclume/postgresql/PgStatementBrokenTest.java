package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
 * A connection that broke in the middle of an answer was reported as "this
 * statement is closed" - what the cleanup said after the fact, not what
 * happened. And a DataRow before any RowDescription was read against the
 * columns of nothing. The break is the error now, and a row without a
 * description is a protocol violation.
 */
@Timeout(30)
class PgStatementBrokenTest {

    private interface Script {
        void answer(DataInputStream in, OutputStream out) throws IOException;
    }

    private static void writeInt(OutputStream out, int value) throws IOException {
        out.write(new byte[] {(byte) (value >>> 24), (byte) (value >>> 16),
            (byte) (value >>> 8), (byte) value});
    }

    private static void message(OutputStream out, char tag, byte[] body) throws IOException {
        out.write(tag);
        writeInt(out, 4 + body.length);
        out.write(body);
    }

    private static byte[] description() throws IOException {
        ByteArrayOutputStream row = new ByteArrayOutputStream();
        row.write(new byte[] {0, 1});
        row.write("v\0".getBytes(StandardCharsets.US_ASCII));
        row.write(new byte[] {0, 0, 0, 0, 0, 0});
        row.write(new byte[] {0, 0, 0, 25});                 // text
        row.write(new byte[] {(byte) 0xff, (byte) 0xff});
        row.write(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
        row.write(new byte[] {0, 0});                        // format: text
        return row.toByteArray();
    }

    private static byte[] dataRow(String value) throws IOException {
        ByteArrayOutputStream row = new ByteArrayOutputStream();
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        row.write(new byte[] {0, 1});
        writeInt(row, bytes.length);
        row.write(bytes);
        return row.toByteArray();
    }

    private static SQLException ask(Script script) throws Exception {
        try (ServerSocket listener = new ServerSocket()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            CompletableFuture<Void> served = CompletableFuture.runAsync(() -> {
                try (Socket socket = listener.accept();
                     DataInputStream in = new DataInputStream(socket.getInputStream())) {
                    OutputStream out = socket.getOutputStream();
                    in.readNBytes(in.readInt() - 4);
                    message(out, 'R', new byte[] {0, 0, 0, 0});
                    message(out, 'Z', new byte[] {'I'});
                    out.flush();
                    in.readByte();
                    in.readNBytes(in.readInt() - 4);
                    script.answer(in, out);
                } catch (IOException gone) {
                    // the client gave up
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
                return assertThrows(SQLException.class, () -> session.askOneValue("select 'x'"));
            } finally {
                served.cancel(true);
            }
        }
    }

    private static String whole(Throwable failure) {
        StringBuilder all = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            all.append(t).append(" / ");
        }
        return all.toString();
    }

    /** Control: holds before and after - the break is the error, and class 08. */
    @Test
    void theRealErrorIsReportedWhenTheConnectionBreaks() throws Exception {
        SQLException failed = ask((in, out) -> {
            message(out, 'T', description());
            message(out, 'D', dataRow("first"));
            byte[] half = dataRow("second");
            out.write('D');
            writeInt(out, 4 + half.length);
            out.write(half, 0, 3);                           // and then the line goes dead
            out.flush();
        });
        String all = whole(failed);
        assertFalse(all.toLowerCase(java.util.Locale.ROOT).contains("is closed"),
                "the cleanup's word, not the break: " + all);
        assertTrue(failed.getSQLState() != null && failed.getSQLState().startsWith("08"),
                "a broken connection is class 08: " + all);
    }

    @Test
    void aDataRowWithoutDescriptionIsRefused() throws Exception {
        SQLException refused = ask((in, out) -> {
            message(out, 'D', dataRow("orphan"));
            message(out, 'C', "SELECT 1\0".getBytes(StandardCharsets.US_ASCII));
            message(out, 'Z', new byte[] {'I'});
            out.flush();
            in.read();
        });
        assertTrue("08P01".equals(refused.getSQLState()), whole(refused));
    }
}
