package space.seclume.mysql;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A MySQL server, as far as it has to go for the tests.
 *
 * <p>Without Docker and without an installation there would otherwise be no way
 * to check the driver <b>as a whole</b> - handshake, login, packet framing with
 * sequence numbers, text and binary results, error packets. A test server is no
 * substitute for the real one (it carries the same assumptions as the driver,
 * and where both are wrong it does not show), but it catches exactly the
 * mistakes that are most common: shifted lengths, wrong sequence numbers, a
 * bitmask with the wrong offset.
 *
 * <p>It checks the login answer <b>itself</b> - with the JCA, from the password
 * the test knows. So a driver sending nonsense does not get through here.
 */
final class FakeMySqlServer implements AutoCloseable {

    /** The scramble this server always sends - fixed, so that tests can compute. */
    static final byte[] SCRAMBLE = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x18, 0x29, 0x3a,
        0x4b, 0x5c, 0x6d, 0x7e, 0x0f, 0x10, 0x21, 0x32, 0x43, 0x54
    };

    /** A column, as the test server describes it. */
    record Column(String name, int type, int flags, long length) {

        Column(String name, int type) {
            this(name, type, 0, 255);
        }
    }

    private final ServerSocket serverSocket;
    private final String expectedUser;
    private final String password;
    private final Thread thread;
    private final CountDownLatch done = new CountDownLatch(1);
    private final AtomicReference<Exception> failure = new AtomicReference<>();
    private final List<String> received = new ArrayList<>();

    /** What the server answers to the next query. */
    private List<Column> columns = List.of();
    private List<List<String>> rows = List.of();
    private String errorMessage;
    /** Whether to refuse the login itself - see {@link #rejectLogin()}. */
    private volatile boolean rejectLogin;
    private volatile boolean stopped;
    /** Whether to switch the login to MariaDB's Kerberos plugin - see {@link #switchToKerberos()}. */
    private volatile boolean kerberos;

    FakeMySqlServer(String user, String password) throws IOException {
        this.serverSocket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        this.expectedUser = user;
        this.password = password;
        this.thread = new Thread(this::serve, "fake-mysql");
        this.thread.setDaemon(true);
    }

    FakeMySqlServer answerWith(List<Column> columns, List<List<String>> rows) {
        this.columns = columns;
        this.rows = rows;
        this.errorMessage = null;
        return this;
    }

    FakeMySqlServer failWith(String message) {
        this.errorMessage = message;
        return this;
    }

    /**
     * Answer the login with an error packet instead of an OK.
     *
     * <p>For the wipe tests: the password has been read, hashed and sent by
     * then, so the refusal arrives while the driver still holds it.
     */
    FakeMySqlServer rejectLogin() {
        this.rejectLogin = true;
        return this;
    }

    /**
     * Answer the login with a switch to {@code auth_gssapi_client}, naming a
     * service principal, as a MariaDB with {@code IDENTIFIED VIA gssapi} does;
     * then wait for the client to give up.
     */
    FakeMySqlServer switchToKerberos() {
        this.kerberos = true;
        return this;
    }

    /**
     * Answer the login with a switch to {@code client_ed25519} or
     * {@code parsec}, and check the signature that comes back - with the
     * JDK: for {@code client_ed25519} against the public key MariaDB documents
     * for the password {@code secret} (so the test must use that password),
     * for {@code parsec} by signing the same scrambles with the JDK's own
     * Ed25519 under the seed the JDK's PBKDF2 derives. Ed25519 is
     * deterministic, so the two signatures must be the same bytes.
     */
    FakeMySqlServer switchToSignature(String plugin) {
        this.signaturePlugin = plugin;
        return this;
    }

    /** The salt this server's parsec ext-salt carries. */
    static final byte[] PARSEC_SALT = "eighteen salt byte".getBytes(StandardCharsets.US_ASCII);
    /** MariaDB's documentation: {@code ed25519_password('secret')}. */
    static final String SECRET_PUBLIC_KEY = "ZIgUREUg5PVgQ6LskhXmO+eZLS0nC8be6HPjYWR4YJY";

    private volatile String signaturePlugin;

    private void signatureLogin(InputStream in, OutputStream out) throws Exception {
        byte[] nonce = new byte[32];
        new java.util.Random(7).nextBytes(nonce);
        ByteArrayOutputStream request = new ByteArrayOutputStream();
        request.write(0xfe);
        request.writeBytes((signaturePlugin + "\0").getBytes(StandardCharsets.US_ASCII));
        request.writeBytes(nonce);
        writePacket(out, request.toByteArray(), 2);
        int sequence = 3;
        if ("parsec".equals(signaturePlugin)) {
            byte[] ask = readPacket(in);
            if (ask.length != 0) {
                throw new IllegalStateException("parsec: expected an empty packet, got "
                        + ask.length + " bytes");
            }
            ByteArrayOutputStream extSalt = new ByteArrayOutputStream();
            extSalt.write('P');
            extSalt.write(0);                                   // 1024 iterations
            extSalt.writeBytes(PARSEC_SALT);
            writePacket(out, extSalt.toByteArray(), 4);
            sequence = 5;
        }
        byte[] answer = readPacket(in);
        boolean right;
        if ("parsec".equals(signaturePlugin)) {
            if (answer.length != 96) {
                throw new IllegalStateException("parsec: expected 96 bytes, got " + answer.length);
            }
            javax.crypto.SecretKeyFactory pbkdf2 =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] seed = pbkdf2.generateSecret(new javax.crypto.spec.PBEKeySpec(
                    password.toCharArray(), PARSEC_SALT, 1024, 256)).getEncoded();
            java.security.Signature jdk = java.security.Signature.getInstance("Ed25519");
            jdk.initSign(java.security.KeyFactory.getInstance("Ed25519").generatePrivate(
                    new java.security.spec.EdECPrivateKeySpec(
                            java.security.spec.NamedParameterSpec.ED25519, seed)));
            jdk.update(nonce);
            jdk.update(answer, 0, 32);
            right = java.util.Arrays.equals(jdk.sign(),
                    java.util.Arrays.copyOfRange(answer, 32, 96));
        } else {
            byte[] raw = java.util.Base64.getDecoder().decode(SECRET_PUBLIC_KEY + "=");
            byte[] prefix = java.util.HexFormat.of().parseHex("302a300506032b6570032100");
            byte[] encoded = new byte[prefix.length + raw.length];
            System.arraycopy(prefix, 0, encoded, 0, prefix.length);
            System.arraycopy(raw, 0, encoded, prefix.length, raw.length);
            java.security.Signature jdk = java.security.Signature.getInstance("Ed25519");
            jdk.initVerify(java.security.KeyFactory.getInstance("Ed25519")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(encoded)));
            jdk.update(nonce);
            right = answer.length == 64 && jdk.verify(answer);
        }
        if (right) {
            sendOk(out, sequence + 1, 0, 0);
        } else {
            sendError(out, sequence + 1, 1045, "28000",
                    "Access denied for user '" + expectedUser + "'@'localhost'");
        }
    }

    FakeMySqlServer start() {
        thread.start();
        return this;
    }

    int port() {
        return serverSocket.getLocalPort();
    }

    /** Answers every COM_RESET_CONNECTION with an error. */
    private volatile boolean refuseReset;

    void refuseReset() {
        refuseReset = true;
    }

    /** The SQL texts that arrived, and {@code <reset>} for each reset - so that a test can check them. */
    List<String> received() {
        return received;
    }

    void rethrowFailure() throws Exception {
        Exception e = failure.get();
        if (e != null) {
            throw e;
        }
    }

    void awaitDone() throws InterruptedException {
        done.await(5, java.util.concurrent.TimeUnit.SECONDS);
    }

    // ---- the procedure ---------------------------------------------------

    /**
     * Accepts connections until the test closes the server - the heap dump
     * test connects several times, the way a pool would.
     */
    private void serve() {
        while (!stopped) {
            try (Socket socket = serverSocket.accept()) {
                session(socket);
            } catch (IOException e) {
                return;          // der Server wurde geschlossen
            } catch (Exception e) {
                failure.set(e);
            } finally {
                done.countDown();
            }
        }
    }

    private void session(Socket socket) throws Exception {
        try (InputStream in = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {
            sendHandshake(out);
            byte[] login = readPacket(in);
            if (rejectLogin) {
                // Checked first anyway: a driver that sends a wrong hash and
                // is then told "wrong password" would pass the test for the
                // wrong reason.
                checkLogin(login);
                sendError(out, 2, 1045, "28000",
                        "Access denied for user '" + expectedUser + "'@'localhost'");
                return;
            }
            checkLogin(login);
            if (kerberos) {
                java.io.ByteArrayOutputStream request = new java.io.ByteArrayOutputStream();
                request.write(0xfe);
                request.writeBytes("auth_gssapi_client\0mariadb/db.test@TEST.REALM\0Kerberos\0"
                        .getBytes(StandardCharsets.US_ASCII));
                writePacket(out, request.toByteArray(), 2);
                try {
                    while (readPacket(in) != null) {
                        // whatever a client that has no ticket still sends
                    }
                } catch (IOException hungUp) {
                    // the client gave up, as it should
                }
                return;
            }
            if (signaturePlugin != null) {
                signatureLogin(in, out);
            } else {
                sendOk(out, 2, 0, 0);
            }

            while (true) {
                byte[] packet;
                try {
                    packet = readPacket(in);
                } catch (IOException e) {
                    return;      // der Treiber hat aufgelegt
                }
                if (packet == null || handleCommand(packet, out)) {
                    return;
                }
            }
        }
    }

    /** @return {@code true} if the client hung up */
    private boolean handleCommand(byte[] packet, OutputStream out) throws Exception {
        int command = packet[0] & 0xff;
        switch (command) {
            case 0x01 -> {                                      // COM_QUIT
                return true;
            }
            case 0x0e -> sendOk(out, 1, 0, 0);                   // COM_PING
            case 0x1f -> {                                      // COM_RESET_CONNECTION
                received.add("<reset>");
                if (refuseReset) {
                    sendError(out, 1, 1041, "HY000", "Out of memory");
                } else {
                    sendOk(out, 1, 0, 0);
                }
            }
            case 0x03 -> {                                      // COM_QUERY
                received.add(new String(packet, 1, packet.length - 1, StandardCharsets.UTF_8));
                if (errorMessage != null) {
                    sendError(out, 1, 1064, "42000", errorMessage);
                } else if (columns.isEmpty()) {
                    sendOk(out, 1, rows.size(), 7);
                } else {
                    sendTextResult(out);
                }
            }
            case 0x16 -> {                                      // COM_STMT_PREPARE
                received.add(new String(packet, 1, packet.length - 1, StandardCharsets.UTF_8));
                sendPrepareResponse(out);
            }
            case 0x17 -> sendBinaryResult(out);                 // COM_STMT_EXECUTE
            case 0x19 -> { }                                    // COM_STMT_CLOSE, keine Antwort
            case 0x1a -> sendOk(out, 1, 0, 0);                  // COM_STMT_RESET
            default -> sendError(out, 1, 1047, "08S01",
                    "unknown command 0x" + Integer.toHexString(command));
        }
        return false;
    }

    private void sendHandshake(OutputStream out) throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(10);                                       // Protokollversion
        payload.writeBytes("8.4.0-fake".getBytes(StandardCharsets.US_ASCII));
        payload.write(0);
        writeInt(payload, 42, 4);                                // Verbindungsnummer
        payload.write(SCRAMBLE, 0, 8);
        payload.write(0);                                        // Fueller
        // Lower capability bits: PROTOCOL_41, SECURE_CONNECTION, CONNECT_WITH_DB, TRANSACTIONS
        int lower = MyCapabilities.PROTOCOL_41 | MyCapabilities.SECURE_CONNECTION
                | MyCapabilities.CONNECT_WITH_DB | MyCapabilities.TRANSACTIONS;
        writeInt(payload, lower & 0xffff, 2);
        payload.write(45);                                       // utf8mb4
        writeInt(payload, 2, 2);                                 // Statusbits: autocommit
        int upper = MyCapabilities.PLUGIN_AUTH | MyCapabilities.PLUGIN_AUTH_LENENC_CLIENT_DATA
                | MyCapabilities.DEPRECATE_EOF | MyCapabilities.CONNECT_ATTRS
                | MyCapabilities.MULTI_RESULTS;
        writeInt(payload, upper >>> 16, 2);
        payload.write(21);                                       // Laenge des Scrambles inkl. Null
        payload.write(new byte[10]);                             // reserviert
        payload.write(SCRAMBLE, 8, 12);
        payload.write(0);
        payload.writeBytes("mysql_native_password".getBytes(StandardCharsets.US_ASCII));
        payload.write(0);
        writePacket(out, payload.toByteArray(), 0);
    }

    /** Checks the login answer with the JCA - independently of the driver code. */
    private void checkLogin(byte[] packet) throws Exception {
        int at = 4 + 4 + 1 + 23;                                 // Bits, Paketgroesse, Zeichensatz, Fueller
        int end = at;
        while (packet[end] != 0) {
            end++;
        }
        String user = new String(packet, at, end - at, StandardCharsets.UTF_8);
        if (!user.equals(expectedUser)) {
            throw new IllegalStateException("expected user " + expectedUser + ", got " + user);
        }
        at = end + 1;
        int responseLength = packet[at++] & 0xff;
        byte[] response = new byte[responseLength];
        System.arraycopy(packet, at, response, 0, responseLength);

        // A user of a signature plugin is switched whatever the first answer
        // was - MariaDB does not check a native hash it has no use for.
        byte[] expected = nativePassword(password);
        if (signaturePlugin == null && !java.util.Arrays.equals(expected, response)) {
            throw new IllegalStateException("the authentication response is wrong");
        }
    }

    private static byte[] nativePassword(String password) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] stage1 = sha1.digest(password.getBytes(StandardCharsets.UTF_8));
        byte[] stage2 = sha1.digest(stage1);
        sha1.reset();
        sha1.update(SCRAMBLE);
        sha1.update(stage2);
        byte[] mask = sha1.digest();
        byte[] result = new byte[20];
        for (int i = 0; i < 20; i++) {
            result[i] = (byte) (stage1[i] ^ mask[i]);
        }
        return result;
    }

    // ---- answers ---------------------------------------------------------

    private void sendOk(OutputStream out, int sequence, long affected, long insertId)
            throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(0x00);
        writeLengthEncoded(payload, affected);
        writeLengthEncoded(payload, insertId);
        writeInt(payload, 2, 2);                                 // Statusbits
        writeInt(payload, 0, 2);                                 // Warnungen
        writePacket(out, payload.toByteArray(), sequence);
    }

    private void sendError(OutputStream out, int sequence, int number, String sqlState,
                           String message) throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(0xff);
        writeInt(payload, number, 2);
        payload.write('#');
        payload.writeBytes(sqlState.getBytes(StandardCharsets.US_ASCII));
        payload.writeBytes(message.getBytes(StandardCharsets.UTF_8));
        writePacket(out, payload.toByteArray(), sequence);
    }

    private void sendTextResult(OutputStream out) throws IOException {
        int sequence = 1;
        ByteArrayOutputStream count = new ByteArrayOutputStream();
        writeLengthEncoded(count, columns.size());
        writePacket(out, count.toByteArray(), sequence++);
        for (Column column : columns) {
            writePacket(out, columnDefinition(column), sequence++);
        }
        for (List<String> row : rows) {
            ByteArrayOutputStream payload = new ByteArrayOutputStream();
            for (String value : row) {
                if (value == null) {
                    payload.write(0xfb);
                } else {
                    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                    writeLengthEncoded(payload, bytes.length);
                    payload.writeBytes(bytes);
                }
            }
            writePacket(out, payload.toByteArray(), sequence++);
        }
        writeEof(out, sequence);
    }

    /**
     * The same rows in the binary format - null bitmask with two bits of
     * lead-in and {@code LONGLONG} as eight bytes, everything else as a
     * string.
     */
    private void sendBinaryResult(OutputStream out) throws IOException {
        int sequence = 1;
        ByteArrayOutputStream count = new ByteArrayOutputStream();
        writeLengthEncoded(count, columns.size());
        writePacket(out, count.toByteArray(), sequence++);
        for (Column column : columns) {
            writePacket(out, columnDefinition(column), sequence++);
        }
        for (List<String> row : rows) {
            ByteArrayOutputStream payload = new ByteArrayOutputStream();
            payload.write(0x00);
            int bitmapLength = (columns.size() + 9) / 8;
            byte[] bitmap = new byte[bitmapLength];
            for (int i = 0; i < row.size(); i++) {
                if (row.get(i) == null) {
                    int bit = i + 2;
                    bitmap[bit / 8] |= (byte) (1 << (bit % 8));
                }
            }
            payload.write(bitmap);
            for (int i = 0; i < row.size(); i++) {
                String value = row.get(i);
                if (value == null) {
                    continue;
                }
                if (columns.get(i).type() == MyTypes.LONGLONG) {
                    writeInt(payload, Long.parseLong(value), 8);
                } else {
                    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                    writeLengthEncoded(payload, bytes.length);
                    payload.writeBytes(bytes);
                }
            }
            writePacket(out, payload.toByteArray(), sequence++);
        }
        writeEof(out, sequence);
    }

    /** With DEPRECATE_EOF the end is an OK packet starting with 0xfe. */
    private void writeEof(OutputStream out, int sequence) throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(0xfe);
        writeLengthEncoded(payload, 0);
        writeLengthEncoded(payload, 0);
        writeInt(payload, 2, 2);
        writeInt(payload, 0, 2);
        writePacket(out, payload.toByteArray(), sequence);
    }

    private void sendPrepareResponse(OutputStream out) throws IOException {
        int sequence = 1;
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(0x00);
        writeInt(payload, 7, 4);                                 // Anweisungsnummer
        writeInt(payload, columns.size(), 2);
        writeInt(payload, 1, 2);                                 // ein Parameter
        payload.write(0);
        writeInt(payload, 0, 2);
        writePacket(out, payload.toByteArray(), sequence++);

        // First the parameter descriptions, then the column ones.
        writePacket(out, columnDefinition(new Column("?", MyTypes.VAR_STRING)), sequence++);
        for (Column column : columns) {
            writePacket(out, columnDefinition(column), sequence++);
        }
    }

    private byte[] columnDefinition(Column column) throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        writeLengthEncodedString(payload, "def");
        writeLengthEncodedString(payload, "testdb");
        writeLengthEncodedString(payload, "t");
        writeLengthEncodedString(payload, "t");
        writeLengthEncodedString(payload, column.name());
        writeLengthEncodedString(payload, column.name());
        writeLengthEncoded(payload, 0x0c);
        writeInt(payload, 45, 2);                                // utf8mb4
        writeInt(payload, column.length(), 4);
        payload.write(column.type());
        writeInt(payload, column.flags(), 2);
        payload.write(0);                                        // Nachkommastellen
        writeInt(payload, 0, 2);                                 // Fueller
        return payload.toByteArray();
    }

    // ---- framing ---------------------------------------------------------

    private void writePacket(OutputStream out, byte[] payload, int sequence) throws IOException {
        out.write(payload.length & 0xff);
        out.write((payload.length >>> 8) & 0xff);
        out.write((payload.length >>> 16) & 0xff);
        out.write(sequence & 0xff);
        out.write(payload);
        out.flush();
    }

    private byte[] readPacket(InputStream in) throws IOException {
        DataInputStream data = new DataInputStream(in);
        int length = (data.readUnsignedByte())
                | (data.readUnsignedByte() << 8)
                | (data.readUnsignedByte() << 16);
        data.readUnsignedByte();                                 // Folgenummer
        byte[] payload = new byte[length];
        data.readFully(payload);
        return payload;
    }

    private static void writeInt(ByteArrayOutputStream out, long value, int length) {
        for (int i = 0; i < length; i++) {
            out.write((int) ((value >>> (8 * i)) & 0xff));
        }
    }

    private static void writeLengthEncoded(ByteArrayOutputStream out, long value) {
        if (value < 251) {
            out.write((int) value);
        } else if (value < 1 << 16) {
            out.write(0xfc);
            writeInt(out, value, 2);
        } else {
            out.write(0xfd);
            writeInt(out, value, 3);
        }
    }

    private static void writeLengthEncodedString(ByteArrayOutputStream out, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        writeLengthEncoded(out, bytes.length);
        out.writeBytes(bytes);
    }

    @Override
    public void close() throws IOException {
        stopped = true;
        serverSocket.close();
    }
}
