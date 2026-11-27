import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * A server that begins Kerberos and skips the end of it. With a real ticket
 * the client sends its first token; the server then answers ReadyForQuery
 * ("Z") - or AuthenticationOk ("R") - without the reply that proves it is the
 * service the ticket was for. Both must be refused with 28000. run with
 * pg.seclume.test pointing at this container, so that the ticket is a real
 * one for postgres/pg.seclume.test.
 */
public class KerberosSkipProof {

    public static void main(String[] args) throws Exception {
        for (char skip : new char[] {'Z', 'R'}) {
            try (ServerSocket listener = new ServerSocket()) {
                listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
                boolean[] tokenCame = new boolean[1];
                Thread server = new Thread(() -> serve(listener, skip, tokenCame));
                server.start();
                String url = "jdbc:seclume:postgresql://pg.seclume.test:" + listener.getLocalPort()
                        + "/postgres?user=alice&tls=off&provider=none";
                try (Connection c = DriverManager.getConnection(url)) {
                    System.out.println("PROOF skip " + skip + ": LET IN");
                } catch (SQLException e) {
                    server.join(10_000);
                    System.out.println("PROOF skip " + skip + ": token sent " + tokenCame[0]
                            + ", refused " + e.getSQLState() + " - " + e.getMessage());
                }
            }
        }
    }

    static void serve(ServerSocket listener, char skip, boolean[] tokenCame) {
        try (Socket socket = listener.accept();
             DataInputStream in = new DataInputStream(socket.getInputStream())) {
            OutputStream out = socket.getOutputStream();
            in.readNBytes(in.readInt() - 4);                     // the startup message
            out.write('R');
            writeInt(out, 8);
            writeInt(out, 7);                                    // AuthenticationGSS
            out.flush();
            if (in.read() != 'p') {
                return;
            }
            in.readNBytes(in.readInt() - 4);                     // the first token
            tokenCame[0] = true;
            if (skip == 'R') {
                out.write('R');
                writeInt(out, 8);
                writeInt(out, 0);                                // AuthenticationOk
            }
            for (int i = 0; i < 2; i++) {
                out.write('Z');
                writeInt(out, 5);
                out.write('I');
            }
            out.flush();
            in.read();
        } catch (IOException gone) {
            // the client hung up
        }
    }

    static void writeInt(OutputStream out, int value) throws IOException {
        out.write(new byte[] {(byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value});
    }
}
