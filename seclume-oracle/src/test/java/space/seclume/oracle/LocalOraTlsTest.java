package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.SecretProviders;

/**
 * TLS against Oracle — and what this test does <b>not</b> prove.
 *
 * <p>Oracle has no negotiation: a TCPS listener speaks TLS from the first byte
 * and a TCP one never does. The client side of that is what is built, and it
 * is what is checked here — the handshake first, the whole NS and TTC protocol
 * inside it, a real login and a real query.
 *
 * <p><b>The listener behind it is a plain one.</b> The test puts a TLS
 * terminator in front of the real Oracle and forwards the decrypted bytes to
 * port 1521. That exercises every line this driver owns, and it does not
 * exercise Oracle's own TCPS listener, because the slim Free image carries no
 * PKI at all: no {@code orapki}, no wallet, no way to serve a certificate. So
 * one thing stays open until somebody runs this against a configured TCPS
 * listener — whether Oracle minds our {@code (PROTOCOL=TCPS)} description in
 * any way we have not seen. Saying that is cheaper than implying a green test
 * means more than it does.
 */
class LocalOraTlsTest {

    private static final String HOST =
            System.getProperty("seclume.oracle.host", space.seclume.tck.TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.oracle.port", 1521);
    private static final String USER =
            System.getProperty("seclume.oracle.user", "seclume_test");
    private static final String SERVICE =
            System.getProperty("seclume.oracle.service", "FREEPDB1");

    private static Path password;
    private static TlsFront front;

    @BeforeAll
    static void startTheFront() throws Exception {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                password = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(password != null, "no .local-oracle-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException e) {
            Assumptions.abort("no Oracle listener on " + HOST + ":" + PORT);
        }
        front = TlsFront.start(HOST, PORT);
    }

    @AfterAll
    static void stopTheFront() {
        if (front != null) {
            front.close();
        }
    }

    private static OracleSession.Settings settings(String host, int port, TlsMode mode)
            throws SQLException {
        return new OracleSession.Settings(host, port, SERVICE, USER,
                SecretProviders.of(Map.of("provider", "file", "path", password.toString())),
                5_000, HostList.of(host, port), ResultLimit.NONE, mode);
    }

    /**
     * The whole protocol inside TLS: handshake, CONNECT, login, query.
     *
     * <p>A query and not just a connection, because the login is short and the
     * interesting failures are in the framing afterwards — a channel that gets
     * TLS record boundaries wrong still logs in and then hangs on the first
     * answer that spans two records.
     */
    @Test
    void speaksTheWholeProtocolInsideTls() throws Exception {
        try (OracleSession session = OracleSession.open(
                settings("127.0.0.1", front.port(), TlsMode.REQUIRE))) {
            String tls = session.tlsDescription();
            assertNotNull(tls, "tls=require connected without encryption");
            System.err.println("[tls] oracle through " + tls);
            assertTrue(tls.startsWith("TLSv1."), tls);

            int[] rows = {0};
            session.query("select 1 from dual", row -> rows[0]++);
            assertTrue(rows[0] == 1, "the query inside TLS returned " + rows[0] + " rows");
        }
    }

    /**
     * Something larger than one TLS record.
     *
     * <p>A record holds 16 KB at most, so an answer of a few hundred rows is
     * reassembled from several — which is the part of the channel that a
     * one-row query never touches.
     */
    @Test
    void carriesAnAnswerAcrossManyRecords() throws Exception {
        try (OracleSession session = OracleSession.open(
                settings("127.0.0.1", front.port(), TlsMode.REQUIRE))) {
            int[] rows = {0};
            session.query("select rpad('x', 200, 'x') from dual connect by level <= 500",
                    row -> rows[0]++);
            assertTrue(rows[0] == 500, "expected 500 rows, got " + rows[0]);
        }
    }

    /** {@code verify-full}: a certificate signed by nobody is refused. */
    @Test
    void verifyFullRefusesTheSelfSignedCertificate() {
        SQLException failure = assertThrows(SQLException.class,
                () -> OracleSession.open(settings("127.0.0.1", front.port(),
                        TlsMode.VERIFY_FULL)));
        System.err.println("[tls] verify-full: " + failure.getMessage());
    }

    /** The connect description says TCPS when TLS is asked for, and TCP otherwise. */
    @Test
    void theDescriptionNamesTheProtocol() throws Exception {
        assertTrue(settings(HOST, PORT, TlsMode.REQUIRE).connectString().contains("PROTOCOL=TCPS"),
                "require did not ask for TCPS");
        assertTrue(settings(HOST, PORT, TlsMode.OFF).connectString().contains("PROTOCOL=TCP)"),
                "off did not ask for TCP");
    }

    /** {@code off} against the plain listener - unchanged, and still working. */
    @Test
    void offStaysInTheClear() throws Exception {
        try (OracleSession session = OracleSession.open(settings(HOST, PORT, TlsMode.OFF))) {
            assertTrue(session.tlsDescription() == null);
            session.query("select 1 from dual", row -> { });
        }
    }

    /**
     * A TLS terminator in front of the real listener.
     *
     * <p>The certificate is made at test time with {@code keytool} into a
     * temporary directory — nothing here is committed, and nothing here is a
     * secret worth keeping.
     */
    private static final class TlsFront implements AutoCloseable {

        private final SSLServerSocket socket;
        private final Thread accepting;
        private volatile boolean stopped;

        private TlsFront(SSLServerSocket socket, String targetHost, int targetPort) {
            this.socket = socket;
            this.accepting = new Thread(() -> {
                while (!stopped) {
                    try {
                        Socket client = socket.accept();
                        Socket server = new Socket();
                        server.connect(new InetSocketAddress(targetHost, targetPort), 5_000);
                        pump(client, server);
                        pump(server, client);
                    } catch (IOException e) {
                        if (!stopped) {
                            System.err.println("[tls-front] " + e.getMessage());
                        }
                    }
                }
            }, "tls-front");
            this.accepting.setDaemon(true);
            this.accepting.start();
        }

        private static void pump(Socket from, Socket to) {
            Thread thread = new Thread(() -> {
                byte[] buffer = new byte[16 * 1024];
                try (InputStream in = from.getInputStream();
                     OutputStream out = to.getOutputStream()) {
                    int read;
                    while ((read = in.read(buffer)) >= 0) {
                        out.write(buffer, 0, read);
                        out.flush();
                    }
                } catch (IOException closed) {
                    // The end of a connection is not an event here.
                } finally {
                    try {
                        from.close();
                    } catch (IOException ignored) {
                        // nothing left to do
                    }
                    try {
                        to.close();
                    } catch (IOException ignored) {
                        // nothing left to do
                    }
                }
            });
            thread.setDaemon(true);
            thread.start();
        }

        static TlsFront start(String targetHost, int targetPort) throws Exception {
            Path directory = Files.createTempDirectory("seclume-tls-front");
            Path store = directory.resolve("keystore.p12");
            String secret = "changeit";     // a throwaway store, made and deleted here
            Process keytool = new ProcessBuilder(
                    Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                    "-genkeypair", "-alias", "front", "-keyalg", "RSA", "-keysize", "2048",
                    "-validity", "1", "-dname", "CN=localhost",
                    "-keystore", store.toString(), "-storetype", "PKCS12",
                    "-storepass", secret, "-keypass", secret)
                    .redirectErrorStream(true)
                    .start();
            if (keytool.waitFor() != 0) {
                Assumptions.abort("keytool could not make a certificate for the test");
            }
            java.security.KeyStore keys = java.security.KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(store)) {
                keys.load(in, secret.toCharArray()); // seclume-allow: a throwaway test store, not a database password
            }
            KeyManagerFactory managers =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            managers.init(keys, secret.toCharArray()); // seclume-allow: a throwaway test store, not a database password
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(managers.getKeyManagers(), null, null);

            SSLServerSocketFactory factory = context.getServerSocketFactory();
            SSLServerSocket listening = (SSLServerSocket) factory.createServerSocket(
                    0, 16, InetAddress.getLoopbackAddress());
            return new TlsFront(listening, targetHost, targetPort);
        }

        int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() {
            stopped = true;
            try {
                socket.close();
            } catch (IOException ignored) {
                // on close an error has no consequences
            }
        }
    }
}
