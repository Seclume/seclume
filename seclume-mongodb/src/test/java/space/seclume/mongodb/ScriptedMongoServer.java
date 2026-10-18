package space.seclume.mongodb;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

final class ScriptedMongoServer implements AutoCloseable {

    static final byte[] SALT = "somesalt12345678".getBytes(StandardCharsets.US_ASCII);
    static final int ITERATIONS = 4096;

    enum Mode {
        NORMAL,
        NO_SCRAM_SHA_256,
        LOW_ITERATIONS,
        BAD_SERVER_NONCE,
        WRONG_SERVER_SIG,
        DROP_AFTER_HELLO,
        /** Takes saslStart and then says nothing, the connection left open. */
        SILENT_AFTER_SASL_START
    }

    private final SSLServerSocket serverSocket;
    private final Path tempDir;
    private final Path certFile;
    private final Mode mode;
    private final String expectedUser;
    private final byte[] serverKey;
    private final Thread thread;
    private volatile boolean closed;
    private volatile Path proofDumpFile;

    private ScriptedMongoServer(SSLServerSocket serverSocket, Path tempDir, Path certFile,
                                Mode mode, String user, byte[] serverKey) {
        this.serverSocket = serverSocket;
        this.tempDir = tempDir;
        this.certFile = certFile;
        this.mode = mode;
        this.expectedUser = user;
        this.serverKey = serverKey != null ? serverKey.clone() : new byte[32];
        this.thread = Thread.ofVirtual().start(this::serve);
    }

    void setProofDumpFile(Path path) {
        this.proofDumpFile = path;
    }

    static ScriptedMongoServer start(Path tempDir, Mode mode, String user, byte[] serverKey)
            throws Exception {
        boolean windows = System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
        Path keytool = Path.of(System.getProperty("java.home"), "bin",
                windows ? "keytool.exe" : "keytool");
        Path keystore = tempDir.resolve("keystore.p12");
        Path cert = tempDir.resolve("cert.pem");

        Process p1 = new ProcessBuilder(keytool.toString(), "-genkeypair", "-keyalg", "EC",
                "-groupname", "secp256r1", "-alias", "server", "-dname", "CN=localhost",
                "-ext", "san=dns:localhost,ip:127.0.0.1", "-keystore", keystore.toString(),
                "-storepass", "password", "-keypass", "password", "-storetype", "PKCS12")
                .redirectErrorStream(true).start();
        int rc1 = p1.waitFor();
        if (rc1 != 0) {
            throw new IOException("keytool genkeypair failed with code " + rc1 + ": "
                    + new String(p1.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        }

        Process p2 = new ProcessBuilder(keytool.toString(), "-exportcert", "-alias", "server",
                "-keystore", keystore.toString(), "-storepass", "password", "-rfc",
                "-file", cert.toString())
                .redirectErrorStream(true).start();
        int rc2 = p2.waitFor();
        if (rc2 != 0) {
            throw new IOException("keytool exportcert failed with code " + rc2);
        }

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            ks.load(in, "password".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "password".toCharArray());
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), null, null);

        SSLServerSocket socket = (SSLServerSocket) sslContext.getServerSocketFactory()
                .createServerSocket(0, 5, InetAddress.getLoopbackAddress());
        socket.setEnabledProtocols(new String[] {"TLSv1.3"});
        return new ScriptedMongoServer(socket, tempDir, cert, mode, user, serverKey);
    }

    static ScriptedMongoServer startWithPassword(Path tempDir, Mode mode, String user,
                                                String password) throws Exception {
        byte[] pwBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] key = deriveServerKey(pwBytes, SALT, ITERATIONS);
        Arrays.fill(pwBytes, (byte) 0);
        return start(tempDir, mode, user, key);
    }

    static byte[] deriveServerKey(byte[] password, byte[] salt, int iterations) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        char[] chars = new char[password.length];
        for (int i = 0; i < password.length; i++) {
            chars[i] = (char) (password[i] & 0xff);
        }
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 256);
        byte[] saltedPassword = factory.generateSecret(spec).getEncoded();
        Arrays.fill(chars, '\0');

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(saltedPassword, "HmacSHA256"));
        byte[] key = mac.doFinal("Server Key".getBytes(StandardCharsets.US_ASCII));
        Arrays.fill(saltedPassword, (byte) 0);
        return key;
    }

    int port() {
        return serverSocket.getLocalPort();
    }

    Path certFile() {
        return certFile;
    }

    private void serve() {
        while (!closed) {
            try {
                SSLSocket client = (SSLSocket) serverSocket.accept();
                client.setSoTimeout(10_000);
                Thread.ofVirtual().start(() -> handleClient(client));
            } catch (IOException e) {
                if (closed) {
                    break;
                }
            }
        }
    }

    private void handleClient(SSLSocket client) {
        try (client;
             DataInputStream in = new DataInputStream(client.getInputStream());
             OutputStream out = client.getOutputStream()) {

            // Step 1: saslStart
            byte[] saslStartReq = readOpMsg(in);
            int saslStartId = requestId(saslStartReq);
            if (mode == Mode.DROP_AFTER_HELLO) {
                return;
            }
            if (mode == Mode.SILENT_AFTER_SASL_START) {
                // Holds the connection until the client gives up on it -
                // through this socket's own read timeout, which would
                // otherwise end the silence for the client.
                while (!closed) {
                    try {
                        if (in.read() < 0) {
                            return;
                        }
                    } catch (java.net.SocketTimeoutException stillSilent) {
                        // keep holding it
                    }
                }
                return;
            }
            if (mode == Mode.NO_SCRAM_SHA_256) {
                sendOpMsg(out, saslStartId, makeBsonErrorReply("server does not offer SCRAM-SHA-256", 2));
                return;
            }
            String clientFirst = extractBinaryPayload(saslStartReq);
            // clientFirst: n,,n=<user>,r=<clientNonce>
            int rIdx = clientFirst.indexOf("r=");
            String clientNonce = clientFirst.substring(rIdx + 2);
            int comma = clientNonce.indexOf(',');
            if (comma > 0) {
                clientNonce = clientNonce.substring(0, comma);
            }

            String serverNonce;
            if (mode == Mode.BAD_SERVER_NONCE) {
                serverNonce = "maliciousnonce123456789";
            } else {
                serverNonce = clientNonce + "servernonceABCDEF123456";
            }

            int iterations = mode == Mode.LOW_ITERATIONS ? 1000 : ITERATIONS;
            String saltBase64 = Base64.getEncoder().encodeToString(SALT);

            String serverFirst = "r=" + serverNonce + ",s=" + saltBase64 + ",i=" + iterations;
            sendOpMsg(out, saslStartId, makeBsonSaslReply(1, false, serverFirst));

            // Step 3: saslContinue
            byte[] saslContinueReq = readOpMsg(in);
            int saslContinueId = requestId(saslContinueReq);
            String clientFinal = extractBinaryPayload(saslContinueReq);
            // clientFinal: c=biws,r=<serverNonce>,p=<proof>

            int pIdx = clientFinal.indexOf(",p=");
            if (pIdx > 0 && proofDumpFile != null) {
                String proofBase64 = clientFinal.substring(pIdx + 3);
                Files.writeString(proofDumpFile, proofBase64);
            }

            String serverSignature;
            if (mode == Mode.WRONG_SERVER_SIG) {
                serverSignature = "d3JvbmdzaWduYXR1cmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
            } else {
                String clientFirstBare = clientFirst.substring(clientFirst.indexOf("n="));
                String clientFinalWithoutProof = clientFinal.substring(0, pIdx);
                String authMessage = clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof;

                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(serverKey, "HmacSHA256"));
                byte[] sig = mac.doFinal(authMessage.getBytes(StandardCharsets.UTF_8));
                serverSignature = Base64.getEncoder().encodeToString(sig);
            }

            sendOpMsg(out, saslContinueId, makeBsonSaslReply(1, true, "v=" + serverSignature));

            // Step 4+: Subsequent driver commands (driver's hello, ping, etc.)
            while (!client.isClosed()) {
                byte[] cmdReq;
                try {
                    cmdReq = readOpMsg(in);
                } catch (IOException e) {
                    break;
                }
                int cmdId = requestId(cmdReq);
                sendOpMsg(out, cmdId, makeBsonGenericOkReply());
            }

        } catch (Exception ignored) {
        }
    }

    private static int requestId(byte[] opMsg) {
        return ByteBuffer.wrap(opMsg).order(ByteOrder.LITTLE_ENDIAN).getInt(4);
    }

    private static byte[] readOpMsg(DataInputStream in) throws IOException {
        int length = Integer.reverseBytes(in.readInt());
        byte[] body = in.readNBytes(length - 4);
        byte[] full = new byte[length];
        ByteBuffer.wrap(full).order(ByteOrder.LITTLE_ENDIAN).putInt(length).put(body);
        return full;
    }

    private static void sendOpMsg(OutputStream out, int responseTo, byte[] bsonDoc) throws IOException {
        int totalLength = 16 + 4 + 1 + bsonDoc.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLength).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(totalLength);
        buf.putInt(1); // requestId
        buf.putInt(responseTo); // responseTo
        buf.putInt(2013); // opCode OP_MSG
        buf.putInt(0); // flagBits
        buf.put((byte) 0); // section 0
        buf.put(bsonDoc);
        out.write(buf.array());
        out.flush();
    }

    private static String extractBinaryPayload(byte[] opMsg) {
        ByteBuffer buf = ByteBuffer.wrap(opMsg).order(ByteOrder.LITTLE_ENDIAN);
        buf.position(21); // start of BSON
        int docLen = buf.getInt();
        int end = 21 + docLen - 1;
        while (buf.position() < end) {
            byte type = buf.get();
            String name = readCString(buf);
            if ("payload".equals(name) && type == 0x05) {
                int binLen = buf.getInt();
                byte subtype = buf.get();
                byte[] bytes = new byte[binLen];
                buf.get(bytes);
                return new String(bytes, StandardCharsets.UTF_8);
            } else if (type == 0x02) { // String
                int len = buf.getInt();
                buf.position(buf.position() + len);
            } else if (type == 0x10) { // Int32
                buf.position(buf.position() + 4);
            } else if (type == 0x01) { // Double
                buf.position(buf.position() + 8);
            } else if (type == 0x08) { // Boolean
                buf.position(buf.position() + 1);
            }
        }
        return "";
    }

    private static String readCString(ByteBuffer buf) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte b;
        while ((b = buf.get()) != 0) {
            baos.write(b);
        }
        return baos.toString(StandardCharsets.US_ASCII);
    }

    private static byte[] makeBsonHelloReply(boolean includeScram256) throws IOException {
        ByteArrayOutputStream doc = new ByteArrayOutputStream();
        writeDouble(doc, "ok", 1.0);
        ByteArrayOutputStream array = new ByteArrayOutputStream();
        if (includeScram256) {
            writeString(array, "0", "SCRAM-SHA-256");
            writeString(array, "1", "SCRAM-SHA-1");
        } else {
            writeString(array, "0", "SCRAM-SHA-1");
        }
        byte[] arrBytes = array.toByteArray();
        doc.write(0x04);
        writeCString(doc, "saslSupportedMechs");
        writeIntLE(doc, arrBytes.length + 5);
        doc.writeBytes(arrBytes);
        doc.write(0);

        byte[] body = doc.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeIntLE(out, body.length + 5);
        out.writeBytes(body);
        out.write(0);
        return out.toByteArray();
    }

    private static byte[] makeBsonSaslReply(int convId, boolean done, String payload) throws IOException {
        ByteArrayOutputStream doc = new ByteArrayOutputStream();
        writeDouble(doc, "ok", 1.0);
        writeInt32(doc, "conversationId", convId);
        writeBoolean(doc, "done", done);
        writeBinary(doc, "payload", payload.getBytes(StandardCharsets.UTF_8));

        byte[] body = doc.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeIntLE(out, body.length + 5);
        out.writeBytes(body);
        out.write(0);
        return out.toByteArray();
    }

    private static byte[] makeBsonErrorReply(String errmsg, int code) throws IOException {
        ByteArrayOutputStream doc = new ByteArrayOutputStream();
        writeDouble(doc, "ok", 0.0);
        writeString(doc, "errmsg", errmsg);
        writeInt32(doc, "code", code);

        byte[] body = doc.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeIntLE(out, body.length + 5);
        out.writeBytes(body);
        out.write(0);
        return out.toByteArray();
    }

    private static byte[] makeBsonGenericOkReply() throws IOException {
        ByteArrayOutputStream doc = new ByteArrayOutputStream();
        writeDouble(doc, "ok", 1.0);
        writeBoolean(doc, "isWritablePrimary", true);
        writeInt32(doc, "maxBsonObjectSize", 16777216);
        writeInt32(doc, "maxMessageSizeBytes", 48000000);
        writeInt32(doc, "maxWriteBatchSize", 100000);
        writeInt32(doc, "logicalSessionTimeoutMinutes", 30);
        writeInt32(doc, "minWireVersion", 0);
        writeInt32(doc, "maxWireVersion", 21);

        byte[] body = doc.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeIntLE(out, body.length + 5);
        out.writeBytes(body);
        out.write(0);
        return out.toByteArray();
    }

    private static void writeDouble(OutputStream out, String name, double v) throws IOException {
        out.write(0x01);
        writeCString(out, name);
        long bits = Double.doubleToRawLongBits(v);
        for (int i = 0; i < 8; i++) {
            out.write((int) (bits >> (8 * i)));
        }
    }

    private static void writeInt32(OutputStream out, String name, int v) throws IOException {
        out.write(0x10);
        writeCString(out, name);
        writeIntLE(out, v);
    }

    private static void writeBoolean(OutputStream out, String name, boolean b) throws IOException {
        out.write(0x08);
        writeCString(out, name);
        out.write(b ? 1 : 0);
    }

    private static void writeString(OutputStream out, String name, String s) throws IOException {
        out.write(0x02);
        writeCString(out, name);
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        writeIntLE(out, bytes.length + 1);
        out.write(bytes);
        out.write(0);
    }

    private static void writeBinary(OutputStream out, String name, byte[] data) throws IOException {
        out.write(0x05);
        writeCString(out, name);
        writeIntLE(out, data.length);
        out.write(0x00);
        out.write(data);
    }

    private static void writeCString(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.US_ASCII));
        out.write(0);
    }

    private static void writeIntLE(OutputStream out, int v) throws IOException {
        out.write(v & 0xff);
        out.write((v >> 8) & 0xff);
        out.write((v >> 16) & 0xff);
        out.write((v >> 24) & 0xff);
    }

    @Override
    public void close() {
        closed = true;
        try {
            serverSocket.close();
        } catch (IOException ignored) {
        }
    }
}
