package space.seclume.bench;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * A PostgreSQL server that only ever answers rows - so that decoding can be
 * measured without a database.
 *
 * <p>Three measurements in a row have ended with "the mechanism is measured,
 * the end-to-end number needs a local PostgreSQL". There is none to spare on
 * these machines, and the one on the LAN turns every large result into a
 * measurement of the network: a hundred thousand rows are sixty milliseconds
 * of transfer, and a saving of two disappears into it.
 *
 * <p>So this stands in for it. It speaks enough of the wire protocol for
 * <b>both</b> drivers - this one and pgjdbc - to log in, prepare, execute and
 * read a canned result over loopback. What is compared is then what the two do
 * with the same bytes, which is exactly the claim the speed strand makes about
 * large results.
 *
 * <p><b>What it is not.</b> It is not a server, it runs no SQL, and it will
 * happily answer a syntax error with rows. A measurement against it says how
 * fast a driver decodes, not whether it is right - the tests against the real
 * four say that, and nothing here replaces them.
 *
 * <pre>
 * java -cp seclume-bench.jar space.seclume.bench.FakePostgres 5499 100000
 * </pre>
 */
public final class FakePostgres implements AutoCloseable {

    /** Type oids, as the real server sends them. */
    private static final int INT4 = 23;
    private static final int TEXT = 25;
    private static final int NUMERIC = 1700;

    /** How many columns the canned result has. */
    private static final int COLUMNS = 3;

    private static final int SSL_REQUEST = 80877103;
    private static final int CANCEL_REQUEST = 80877102;

    private final ServerSocket socket;
    private final int rows;
    private volatile boolean stopping;

    public FakePostgres(int port, int rows) throws IOException {
        this.rows = rows;
        // A benchmark stand-in on the loopback address.
        this.socket = new ServerSocket(port, 16, InetAddress.getLoopbackAddress()); // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        Thread thread = new Thread(this::accept, "fake-postgres");
        thread.setDaemon(true);
        thread.start();
    }

    public int port() {
        return socket.getLocalPort();
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 5499;
        int rows = args.length > 1 ? Integer.parseInt(args[1]) : 100_000;
        try (FakePostgres server = new FakePostgres(port, rows)) {
            System.out.println("fake postgres on 127.0.0.1:" + server.port()
                    + ", every select answers " + rows + " rows of i/text/numeric");
            System.out.println("stop it with ctrl-c");
            Thread.currentThread().join();
        }
    }

    private void accept() {
        while (!stopping) {
            try {
                Socket client = socket.accept();
                Thread worker = new Thread(() -> serve(client), "fake-postgres-client");
                worker.setDaemon(true);
                worker.start();
            } catch (IOException e) {
                if (!stopping) {
                    System.err.println("fake postgres stopped accepting: " + e);
                }
                return;
            }
        }
    }

    private void serve(Socket client) {
        try (Socket open = client) {
            open.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(
                    new java.io.BufferedInputStream(open.getInputStream(), 1 << 16));
            OutputStream out = new java.io.BufferedOutputStream(
                    open.getOutputStream(), 1 << 16);
            Session session = new Session();
            if (session.startUp(in, out)) {
                session.conversation(in, out);
            }
        } catch (IOException e) {
            // A client that goes away at the end of a run is the normal case;
            // anything else has to be seen. A rig that fails quietly sends the
            // person measuring to look for the fault in the driver.
            String reason = String.valueOf(e.getMessage());
            if (!reason.contains("forcibly closed") && !reason.contains("reset")
                    && !reason.contains("aborted") && !"null".equals(reason)) {
                System.err.println("fake postgres gave up on a client: " + e);
            }
        } catch (RuntimeException e) {
            System.err.println("fake postgres broke: " + e);
        }
    }

    /**
     * One client, with the state that belongs to it.
     *
     * <p>Which format the rows go out in is a property of the connection that
     * asked, so it cannot sit on the server: the two drivers are measured one
     * after the other, one of them asks for binary, and a cached block shared
     * between them would serve the second the first one's bytes. That is the
     * kind of defect a rig hides rather than reports, which is why this is a
     * class and not three fields.
     */
    private final class Session {

        private boolean[] binaryColumns = new boolean[COLUMNS];
        private byte[] canned; // seclume-allow: generated measurement rows, no secret in this module
        private boolean[] cannedFormat;

    /**
     * Login, with no authentication at all.
     *
     * <p>An SSLRequest is answered with {@code N} rather than refused: pgjdbc
     * asks by default, and a rig that needs a certificate set up before it can
     * be used is a rig nobody starts.
     */
        private boolean startUp(DataInputStream in, OutputStream out) throws IOException {
            int length = in.readInt();
            int code = in.readInt();
            if (code == SSL_REQUEST) {
                out.write('N');
                out.flush();
                length = in.readInt();
                code = in.readInt();
            }
            if (code == CANCEL_REQUEST) {
                return false;
            }
            in.readNBytes(length - 8);                    // the parameters, unread

            write(out, 'R', intBytes(0));                 // AuthenticationOk
            parameter(out, "server_version", "18.0");
            parameter(out, "client_encoding", "UTF8");
            parameter(out, "DateStyle", "ISO, MDY");
            parameter(out, "integer_datetimes", "on");
            parameter(out, "standard_conforming_strings", "on");
            parameter(out, "TimeZone", "UTC");
            ByteArrayOutputStream key = new ByteArrayOutputStream();
            key.writeBytes(intBytes(4711));               // BackendKeyData: the pid
            key.writeBytes(intBytes(1234));               // and its secret
            write(out, 'K', key.toByteArray());
            ready(out);
            return true;
        }

        private void conversation(DataInputStream in, OutputStream out) throws IOException {
            while (true) {
                int type = in.read();
                if (type < 0 || type == 'X') {            // Terminate, or gone
                    return;
                }
                int length = in.readInt();
                byte[] body = in.readNBytes(length - 4); // seclume-allow: a query and its parameters, no secret in this module
                switch (type) {
                    case 'Q' -> {
                        if (wantsRows(body)) {
                            describe(out);
                            rows(out);
                        }
                        complete(out);
                        ready(out);
                    }
                    case 'P' -> write(out, '1', new byte[0]);   // ParseComplete
                    case 'B' -> {
                        binaryColumns = resultFormats(body);
                        write(out, '2', new byte[0]);          // BindComplete
                    }
                    case 'C' -> write(out, '3', new byte[0]);   // CloseComplete
                    case 'D' -> describe(out);
                    case 'E' -> {
                        rows(out);
                        complete(out);
                    }
                    case 'S' -> ready(out);
                    case 'H' -> out.flush();
                    default -> {
                        // Anything else is not part of what is being measured.
                    }
                }
                out.flush();
            }
        }

        /**
         * The result format codes a Bind asked for.
         *
         * <p>They have to be read rather than assumed. pgjdbc switches a statement
         * to <b>binary</b> transfer once it has run it a few times - that is its
         * real behaviour against a real server, and a rig that ignored the request
         * would hand it text it then reads as binary. The first run of this server
         * did exactly that and pgjdbc failed with an
         * {@code ArrayIndexOutOfBoundsException} inside its own int4 decoder,
         * which is a confusing way to find out that the rig was lying.
         */
        private boolean[] resultFormats(byte[] bind) {
            int at = skipCString(bind, 0);                 // the portal
            at = skipCString(bind, at);                    // the statement
            int parameterFormats = readShort(bind, at);
            at += 2 + parameterFormats * 2;
            int parameters = readShort(bind, at);
            at += 2;
            for (int i = 0; i < parameters; i++) {
                int length = readInt(bind, at);
                at += 4 + (length < 0 ? 0 : length);
            }
            int formats = readShort(bind, at);
            at += 2;
            boolean[] binary = new boolean[COLUMNS];
            for (int column = 0; column < COLUMNS; column++) {
                int code = formats == 0 ? 0 : readShort(bind, at + Math.min(column, formats - 1) * 2);
                binary[column] = code == 1;
            }
            return binary;
        }

        private static int skipCString(byte[] body, int at) {
            while (at < body.length && body[at] != 0) {
                at++;
            }
            return at + 1;
        }

        private static int readShort(byte[] body, int at) {
            return ((body[at] & 0xff) << 8) | (body[at + 1] & 0xff);
        }

        private static int readInt(byte[] body, int at) {
            return ((body[at] & 0xff) << 24) | ((body[at + 1] & 0xff) << 16)
                    | ((body[at + 2] & 0xff) << 8) | (body[at + 3] & 0xff);
        }

        /**
         * Whether a simple query should be answered with the canned result.
         *
         * <p>What a driver sends on its own account - {@code SET
         * extra_float_digits}, {@code BEGIN}, {@code COMMIT} - gets a bare
         * CommandComplete. A client answered with rows where it expects none goes
         * out of step and blames the statement after next.
         */
        private boolean wantsRows(byte[] body) {
            int end = 0;
            while (end < body.length && body[end] != 0) {
                end++;
            }
            String sql = new String(body, 0, end, StandardCharsets.UTF_8) // seclume-allow: the query text, no secret in this module
                    .trim().toLowerCase(java.util.Locale.ROOT);
            return sql.startsWith("select") || sql.startsWith("with");
        }

        private void describe(OutputStream out) throws IOException {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.writeBytes(shortBytes(COLUMNS));
            field(body, "i", INT4, 4, binaryColumns[0]);
            field(body, "t", TEXT, -1, binaryColumns[1]);
            field(body, "n", NUMERIC, -1, binaryColumns[2]);
            write(out, 'T', body.toByteArray());
        }

        private void field(ByteArrayOutputStream body, String name, int oid, int width,
                           boolean binary) {
            body.writeBytes(name.getBytes(StandardCharsets.UTF_8)); // seclume-allow: a column name, no secret in this module
            body.write(0);
            body.writeBytes(intBytes(0));                 // no table
            body.writeBytes(shortBytes(0));               // no column number
            body.writeBytes(intBytes(oid));
            body.writeBytes(shortBytes(width));
            body.writeBytes(intBytes(-1));                // no type modifier
            body.writeBytes(shortBytes(binary ? 1 : 0));
        }

        /**
         * The rows - built once and written as one block.
         *
         * <p>A rig that spends its time formatting numbers measures itself, so the
         * bytes are assembled on the first call and kept. The client sees the same
         * stream every time, which is also what makes two runs comparable.
         */
        private void rows(OutputStream out) throws IOException {
            byte[] block = canned;
            if (block == null || !java.util.Arrays.equals(cannedFormat, binaryColumns)) {
                block = null;
            }
            if (block == null) {
                ByteArrayOutputStream all = new ByteArrayOutputStream(rows * 48);
                for (int i = 1; i <= rows; i++) {
                    ByteArrayOutputStream row = new ByteArrayOutputStream(48);
                    row.writeBytes(shortBytes(COLUMNS));
                    if (binaryColumns[0]) {
                        row.writeBytes(intBytes(4));
                        row.writeBytes(intBytes(i));
                    } else {
                        cell(row, Integer.toString(i));
                    }
                    cell(row, "text-" + i);                // text is its own binary
                    if (binaryColumns[2]) {
                        throw new IOException("this rig serves numeric as text only - "
                                + "connect with binaryTransfer=false, or teach it the "
                                + "binary numeric format");
                    }
                    cell(row, i + ".5");
                    all.write('D');
                    all.writeBytes(intBytes(row.size() + 4));
                    all.writeBytes(row.toByteArray());
                }
                block = all.toByteArray();
                canned = block;
                cannedFormat = binaryColumns.clone();
            }
            out.write(block);
        }

        private void cell(ByteArrayOutputStream row, String value) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8); // seclume-allow: generated measurement data, no secret in this module
            row.writeBytes(intBytes(bytes.length));
            row.writeBytes(bytes);
        }

        private void complete(OutputStream out) throws IOException {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.writeBytes(("SELECT " + rows).getBytes(StandardCharsets.UTF_8)); // seclume-allow: a command tag, no secret in this module
            body.write(0);
            write(out, 'C', body.toByteArray());
        }

        private void ready(OutputStream out) throws IOException {
            write(out, 'Z', new byte[] {'I'});
            out.flush();
        }

        private void parameter(OutputStream out, String name, String value) throws IOException {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.writeBytes(name.getBytes(StandardCharsets.UTF_8)); // seclume-allow: a parameter name, no secret in this module
            body.write(0);
            body.writeBytes(value.getBytes(StandardCharsets.UTF_8)); // seclume-allow: a parameter value, no secret in this module
            body.write(0);
            write(out, 'S', body.toByteArray());
        }

        private void write(OutputStream out, char type, byte[] body) throws IOException {
            out.write(type);
            out.write(intBytes(body.length + 4));
            out.write(body);
        }
    }

    private static byte[] intBytes(int value) {
        return new byte[] {(byte) (value >>> 24), (byte) (value >>> 16),
                           (byte) (value >>> 8), (byte) value};
    }

    private static byte[] shortBytes(int value) {
        return new byte[] {(byte) (value >>> 8), (byte) value};
    }

    @Override
    public void close() throws IOException {
        stopping = true;
        socket.close();
    }
}
