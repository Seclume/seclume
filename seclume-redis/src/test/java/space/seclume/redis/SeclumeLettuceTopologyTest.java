package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisConnectionException;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.cluster.RedisClusterClient;
import io.lettuce.core.cluster.api.StatefulRedisClusterConnection;
import space.seclume.tck.NoSecretInHeap;

/**
 * Redis Cluster and Redis Sentinel through {@link SeclumeLettuce}:
 *
 * <ul>
 *   <li>seed nodes at {@code localhost} have a certificate for
 *       {@code dns:localhost} only, while the second cluster shard and the
 *       Sentinel-resolved master at {@code 127.0.0.1} have a certificate for
 *       {@code ip:127.0.0.1} only - so connecting to the discovered node
 *       succeeds only when its certificate is checked against its own
 *       address rather than the seed URL's host;
 *   <li>when a discovered shard or a Sentinel-resolved master presents the
 *       seed's {@code dns:localhost} certificate at {@code 127.0.0.1}, the
 *       connection is refused;
 *   <li>neither the Redis password nor Sentinel's own password appears on the
 *       JVM heap afterwards.
 * </ul>
 */
@Timeout(90)
class SeclumeLettuceTopologyTest {

    private static final String STORE_PASSWORD = "seclume-test-keystore";

    private static Path pkiDir;
    private static Path caPem;
    private static SSLContext localhostTls;
    private static SSLContext loopbackTls;
    private static Path redisSecretFile;
    private static Path sentinelSecretFile;

    @BeforeAll
    static void setUpPkiAndSecrets() throws Exception {
        pkiDir = Files.createTempDirectory("seclume-redis-topology-pki");
        caPem = pkiDir.resolve("ca.pem");
        Path caStore = pkiDir.resolve("ca.p12");
        runKeytool("-genkeypair", "-alias", "ca", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=seclume-redis-test-ca",
                "-ext", "bc:c=ca:true", "-storetype", "PKCS12",
                "-keystore", caStore.toString(),
                "-storepass", STORE_PASSWORD, "-keypass", STORE_PASSWORD);
        runKeytool("-exportcert", "-alias", "ca", "-rfc", "-file", caPem.toString(),
                "-keystore", caStore.toString(), "-storepass", STORE_PASSWORD);

        localhostTls = issueLeaf(caStore, "localhost", "CN=localhost", "san=dns:localhost");
        loopbackTls = issueLeaf(caStore, "loopback", "CN=127.0.0.1", "san=ip:127.0.0.1");

        redisSecretFile = Files.createTempFile("seclume-redis-node", ".pw");
        sentinelSecretFile = Files.createTempFile("seclume-redis-sentinel", ".pw");
        // Written through UTF-8 bytes directly so no test field holds the password String.
        Files.writeString(redisSecretFile,
                "redis-cluster-pw-" + UUID.randomUUID() + "\n");
        Files.writeString(sentinelSecretFile,
                "redis-sentinel-pw-" + UUID.randomUUID() + "\n");
        System.gc();
    }

    @AfterAll
    static void tearDown() throws Exception {
        NoSecretInHeap.assertAbsent(redisSecretFile);
        NoSecretInHeap.assertAbsent(sentinelSecretFile);
        Files.deleteIfExists(redisSecretFile);
        Files.deleteIfExists(sentinelSecretFile);
    }

    @Test
    void clusterOverTlsAndPlainVerifiesEachNodeAndRewritesOnEveryShard() throws Exception {
        byte[] expectedPw = readTrimmedBytes(redisSecretFile);
        try (FakeRedisNode node1 = FakeRedisNode.clusterNode(localhostTls, "orders", expectedPw);
             FakeRedisNode node2 = FakeRedisNode.clusterNode(loopbackTls, "orders", expectedPw)) {
            node1.setClusterPeers("localhost", node1.port(), "127.0.0.1", node2.port());
            node2.setClusterPeers("localhost", node1.port(), "127.0.0.1", node2.port());

            String url = "rediss://localhost:" + node1.port()
                    + "?user=orders&tlsRootCert=" + slash(caPem)
                    + "&provider=file&path=" + slash(redisSecretFile);
            RedisClusterClient cluster = SeclumeLettuce.clusterClient(url);
            try (StatefulRedisClusterConnection<String, String> conn = cluster.connect()) {
                // "b" hashes to slot 3300 (0..8191 -> node1 at localhost);
                // "a" hashes to slot 15495 (8192..16383 -> node2 at 127.0.0.1).
                assertEquals("OK", conn.sync().set("b", "on-first-shard"));
                assertEquals("OK", conn.sync().set("a", "on-second-shard"));
                assertEquals("on-first-shard", conn.sync().get("b"));
                assertEquals("on-second-shard", conn.sync().get("a"));
            } finally {
                cluster.shutdown();
            }
            assertEquals("on-first-shard", node1.store.get("b"));
            assertEquals("on-second-shard", node2.store.get("a"));
            assertTrue(node1.authenticatedCount.get() >= 1);
            assertTrue(node2.authenticatedCount.get() >= 1);
        }

        // Plain TCP cluster across multiple seed nodes:
        try (FakeRedisNode node1 = FakeRedisNode.clusterNode(null, "orders", expectedPw);
             FakeRedisNode node2 = FakeRedisNode.clusterNode(null, "orders", expectedPw)) {
            node1.setClusterPeers("localhost", node1.port(), "127.0.0.1", node2.port());
            node2.setClusterPeers("localhost", node1.port(), "127.0.0.1", node2.port());

            String url = "redis://localhost:" + node1.port() + ",127.0.0.1:" + node2.port()
                    + "?user=orders&provider=file&path=" + slash(redisSecretFile);
            RedisClusterClient cluster = SeclumeLettuce.clusterClient(url);
            try (StatefulRedisClusterConnection<String, String> conn = cluster.connect()) {
                assertEquals("OK", conn.sync().set("b", "plain-1"));
                assertEquals("OK", conn.sync().set("a", "plain-2"));
                assertEquals("plain-1", conn.sync().get("b"));
                assertEquals("plain-2", conn.sync().get("a"));
            } finally {
                cluster.shutdown();
            }
        }
        java.util.Arrays.fill(expectedPw, (byte) 0);
    }

    @Test
    void clusterRefusesADiscoveredShardWhoseCertificateIsForAnotherHost() throws Exception {
        byte[] expectedPw = readTrimmedBytes(redisSecretFile);
        // Node 2 is at 127.0.0.1, but presents the certificate for dns:localhost!
        try (FakeRedisNode node1 = FakeRedisNode.clusterNode(localhostTls, "orders", expectedPw);
             FakeRedisNode node2WithWrongCert = FakeRedisNode.clusterNode(
                     localhostTls, "orders", expectedPw)) {
            node1.setClusterPeers("localhost", node1.port(),
                    "127.0.0.1", node2WithWrongCert.port());
            node2WithWrongCert.setClusterPeers("localhost", node1.port(),
                    "127.0.0.1", node2WithWrongCert.port());

            String url = "rediss://localhost:" + node1.port()
                    + "?user=orders&connectTimeout=2000&timeout=2000&tlsRootCert=" + slash(caPem)
                    + "&provider=file&path=" + slash(redisSecretFile);
            RedisClusterClient cluster = SeclumeLettuce.clusterClient(url);
            try (StatefulRedisClusterConnection<String, String> conn = cluster.connect()) {
                // Slot 3300 on node 1 (localhost) works:
                assertEquals("OK", conn.sync().set("b", "ok-on-node-1"));
                // Slot 15495 on node 2 (127.0.0.1 with dns:localhost cert) must be refused:
                assertThrows(RuntimeException.class, () -> conn.sync().get("a"));
                assertEquals(0, node2WithWrongCert.authenticatedCount.get(),
                        "the password was never sent to the node with the wrong certificate");
            } finally {
                cluster.shutdown();
            }
        } finally {
            java.util.Arrays.fill(expectedPw, (byte) 0);
        }
    }

    @Test
    void sentinelOverTlsVerifiesSentinelAndMasterAndUsesSeparatePasswords() throws Exception {
        byte[] masterPw = readTrimmedBytes(redisSecretFile);
        byte[] sentinelPw = readTrimmedBytes(sentinelSecretFile);
        try (FakeRedisNode master = FakeRedisNode.standaloneNode(loopbackTls, "orders", masterPw);
             FakeRedisNode sentinel = FakeRedisNode.sentinelNode(
                     localhostTls, "guard", sentinelPw, "mymaster", "127.0.0.1", master.port())) {
            String url = "rediss-sentinel://localhost:" + sentinel.port()
                    + "?sentinelMasterId=mymaster"
                    + "&user=orders&provider=file&path=" + slash(redisSecretFile)
                    + "&sentinelUser=guard&sentinel-provider=file&sentinel-path="
                    + slash(sentinelSecretFile)
                    + "&tlsRootCert=" + slash(caPem);
            RedisClient client = SeclumeLettuce.client(url);
            try (StatefulRedisConnection<String, String> conn = client.connect()) {
                assertEquals("OK", conn.sync().set("k", "from-sentinel-master"));
                assertEquals("from-sentinel-master", conn.sync().get("k"));
            } finally {
                client.shutdown();
            }
            assertTrue(sentinel.authenticatedCount.get() >= 1);
            assertTrue(master.authenticatedCount.get() >= 1);
            assertEquals("from-sentinel-master", master.store.get("k"));
        } finally {
            java.util.Arrays.fill(masterPw, (byte) 0);
            java.util.Arrays.fill(sentinelPw, (byte) 0);
        }
    }

    @Test
    void sentinelRefusesAMasterWhoseCertificateDoesNotMatchItsAddress() throws Exception {
        byte[] masterPw = readTrimmedBytes(redisSecretFile);
        // Master is at 127.0.0.1, but presents the certificate for dns:localhost!
        try (FakeRedisNode badMaster = FakeRedisNode.standaloneNode(
                localhostTls, "orders", masterPw);
             FakeRedisNode sentinel = FakeRedisNode.sentinelNode(
                     localhostTls, null, null, "mymaster", "127.0.0.1", badMaster.port())) {
            String url = "rediss://localhost:" + sentinel.port()
                    + "?sentinelMasterId=mymaster&connectTimeout=2000&timeout=2000"
                    + "&user=orders&provider=file&path=" + slash(redisSecretFile)
                    + "&tlsRootCert=" + slash(caPem);
            RedisClient client = SeclumeLettuce.client(url);
            try {
                assertThrows(RedisConnectionException.class, client::connect);
                assertEquals(0, badMaster.authenticatedCount.get(),
                        "the password was never sent to the master with the wrong certificate");
            } finally {
                client.shutdown();
            }
        } finally {
            java.util.Arrays.fill(masterPw, (byte) 0);
        }
    }

    private static byte[] readTrimmedBytes(Path file) throws IOException {
        byte[] raw = Files.readAllBytes(file);
        int len = raw.length;
        while (len > 0 && (raw[len - 1] == '\n' || raw[len - 1] == '\r')) {
            len--;
        }
        byte[] trimmed = java.util.Arrays.copyOf(raw, len);
        java.util.Arrays.fill(raw, (byte) 0);
        return trimmed;
    }

    private static String slash(Path path) {
        return path.toAbsolutePath().normalize().toString().replace('\\', '/');
    }

    private static SSLContext issueLeaf(Path caStore, String alias, String dname, String san)
            throws Exception {
        Path leafStore = pkiDir.resolve(alias + ".p12");
        Path csr = pkiDir.resolve(alias + ".csr");
        Path cert = pkiDir.resolve(alias + ".pem");
        runKeytool("-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", dname, "-storetype", "PKCS12",
                "-keystore", leafStore.toString(),
                "-storepass", STORE_PASSWORD, "-keypass", STORE_PASSWORD);
        runKeytool("-certreq", "-alias", alias, "-file", csr.toString(),
                "-keystore", leafStore.toString(), "-storepass", STORE_PASSWORD);
        runKeytool("-gencert", "-alias", "ca", "-infile", csr.toString(),
                "-outfile", cert.toString(), "-rfc", "-validity", "2",
                "-ext", san, "-keystore", caStore.toString(), "-storepass", STORE_PASSWORD);
        runKeytool("-importcert", "-noprompt", "-alias", "ca", "-file", caPem.toString(),
                "-keystore", leafStore.toString(), "-storepass", STORE_PASSWORD);
        runKeytool("-importcert", "-noprompt", "-alias", alias, "-file", cert.toString(),
                "-keystore", leafStore.toString(), "-storepass", STORE_PASSWORD);

        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(leafStore)) {
            store.load(in, STORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, STORE_PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(kmf.getKeyManagers(), null, null);
        return context;
    }

    private static void runKeytool(String... args) throws Exception {
        String bin = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool")
                .toString();
        List<String> cmd = new ArrayList<>(args.length + 1);
        cmd.add(bin);
        cmd.addAll(List.of(args));
        Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        byte[] output = process.getInputStream().readAllBytes();
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: "
                    + new String(output, StandardCharsets.UTF_8));
        }
    }

    /**
     * Minimal scripted RESP2/RESP3 server for Standalone, Sentinel and Cluster
     * tests over TLS 1.3 or plain TCP.
     */
    private static final class FakeRedisNode implements Closeable {

        private final ServerSocket server;
        private final String expectedUser;
        private final byte[] expectedPassword;
        private final boolean sentinel;
        private final boolean cluster;
        private final String masterName;
        private final String masterHost;
        private final int masterPort;
        private volatile String peer1Host;
        private volatile int peer1Port;
        private volatile String peer2Host;
        private volatile int peer2Port;
        final Map<String, String> store = new ConcurrentHashMap<>();
        final AtomicInteger authenticatedCount = new AtomicInteger();

        private FakeRedisNode(SSLContext tls, String expectedUser, byte[] expectedPassword,
                              boolean sentinel, boolean cluster, String masterName,
                              String masterHost, int masterPort) throws IOException {
            if (tls != null) {
                SSLServerSocket ssl = (SSLServerSocket) tls.getServerSocketFactory()
                        .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
                ssl.setEnabledProtocols(new String[] {"TLSv1.3"});
                this.server = ssl;
            } else {
                this.server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            }
            this.expectedUser = expectedUser;
            this.expectedPassword = expectedPassword == null ? null : expectedPassword.clone();
            this.sentinel = sentinel;
            this.cluster = cluster;
            this.masterName = masterName;
            this.masterHost = masterHost;
            this.masterPort = masterPort;
            Thread.ofVirtual().start(this::acceptLoop);
        }

        static FakeRedisNode standaloneNode(SSLContext tls, String user, byte[] password)
                throws IOException {
            return new FakeRedisNode(tls, user, password, false, false, null, null, 0);
        }

        static FakeRedisNode clusterNode(SSLContext tls, String user, byte[] password)
                throws IOException {
            return new FakeRedisNode(tls, user, password, false, true, null, null, 0);
        }

        static FakeRedisNode sentinelNode(SSLContext tls, String user, byte[] password,
                                          String masterName, String masterHost, int masterPort)
                throws IOException {
            return new FakeRedisNode(tls, user, password, true, false, masterName, masterHost,
                    masterPort);
        }

        void setClusterPeers(String host1, int port1, String host2, int port2) {
            this.peer1Host = host1;
            this.peer1Port = port1;
            this.peer2Host = host2;
            this.peer2Port = port2;
        }

        int port() {
            return server.getLocalPort();
        }

        private void acceptLoop() {
            while (!server.isClosed()) {
                try {
                    Socket socket = server.accept();
                    Thread.ofVirtual().start(() -> serve(socket));
                } catch (IOException closed) {
                    break;
                }
            }
        }

        private void serve(Socket socket) {
            try (socket;
                 InputStream in = new BufferedInputStream(socket.getInputStream());
                 OutputStream out = new BufferedOutputStream(socket.getOutputStream())) {
                boolean authenticated = expectedPassword == null;
                while (true) {
                    List<byte[]> args = readCommand(in);
                    if (args == null || args.isEmpty()) {
                        break;
                    }
                    String cmd = new String(args.get(0), StandardCharsets.US_ASCII)
                            .toUpperCase(Locale.ROOT);
                    switch (cmd) {
                        case "HELLO" -> {
                            int authIdx = -1;
                            for (int i = 1; i < args.size(); i++) {
                                if ("AUTH".equalsIgnoreCase(
                                        new String(args.get(i), StandardCharsets.US_ASCII))) {
                                    authIdx = i;
                                    break;
                                }
                            }
                            if (authIdx >= 0 && authIdx + 2 < args.size()) {
                                String user = new String(args.get(authIdx + 1),
                                        StandardCharsets.US_ASCII);
                                byte[] pw = args.get(authIdx + 2);
                                if (!checkAuth(user, pw)) {
                                    writeError(out, "WRONGPASS invalid username-password pair");
                                    continue;
                                }
                                authenticated = true;
                                authenticatedCount.incrementAndGet();
                            } else if (!authenticated) {
                                writeError(out, "NOAUTH HELLO must be called with the client "
                                        + "already authenticated, otherwise the HELLO AUTH "
                                        + "<user> <pass> option can be used");
                                continue;
                            }
                            String mode = sentinel ? "sentinel" : (cluster ? "cluster" : "standalone");
                            String role = sentinel ? "sentinel" : "master";
                            String reply = "%7\r\n"
                                    + "$6\r\nserver\r\n$5\r\nredis\r\n"
                                    + "$7\r\nversion\r\n$5\r\n8.0.0\r\n"
                                    + "$5\r\nproto\r\n:3\r\n"
                                    + "$2\r\nid\r\n:1\r\n"
                                    + "$4\r\nmode\r\n$" + mode.length() + "\r\n" + mode + "\r\n"
                                    + "$4\r\nrole\r\n$" + role.length() + "\r\n" + role + "\r\n"
                                    + "$7\r\nmodules\r\n*0\r\n";
                            out.write(reply.getBytes(StandardCharsets.US_ASCII));
                            out.flush();
                        }
                        case "AUTH" -> {
                            String user = args.size() >= 3
                                    ? new String(args.get(1), StandardCharsets.US_ASCII)
                                    : "default";
                            byte[] pw = args.get(args.size() - 1);
                            if (checkAuth(user, pw)) {
                                authenticated = true;
                                authenticatedCount.incrementAndGet();
                                writeSimple(out, "OK");
                            } else {
                                writeError(out, "WRONGPASS invalid username-password pair");
                            }
                        }
                        case "PING" -> writeSimple(out, "PONG");
                        case "CLIENT", "READONLY", "QUIT" -> writeSimple(out, "OK");
                        case "COMMAND" -> {
                            out.write("*0\r\n".getBytes(StandardCharsets.US_ASCII));
                            out.flush();
                        }
                        case "INFO" -> writeBulk(out, "redis_version:8.0.0\r\ncluster_enabled:"
                                + (cluster ? "1" : "0") + "\r\n");
                        case "SENTINEL" -> {
                            if (!authenticated) {
                                writeError(out, "NOAUTH Authentication required.");
                                continue;
                            }
                            String sub = args.size() > 1
                                    ? new String(args.get(1), StandardCharsets.US_ASCII)
                                            .toLowerCase(Locale.ROOT)
                                    : "";
                            if ("get-master-addr-by-name".equals(sub)) {
                                String portStr = Integer.toString(masterPort);
                                String reply = "*2\r\n$" + masterHost.length() + "\r\n" + masterHost
                                        + "\r\n$" + portStr.length() + "\r\n" + portStr + "\r\n";
                                out.write(reply.getBytes(StandardCharsets.US_ASCII));
                                out.flush();
                            } else {
                                out.write("*0\r\n".getBytes(StandardCharsets.US_ASCII));
                                out.flush();
                            }
                        }
                        case "PSUBSCRIBE", "SUBSCRIBE" -> {
                            String channel = args.size() > 1
                                    ? new String(args.get(1), StandardCharsets.US_ASCII) : "*";
                            String kind = cmd.toLowerCase(Locale.ROOT);
                            String reply = "*3\r\n$" + kind.length() + "\r\n" + kind + "\r\n$"
                                    + channel.length() + "\r\n" + channel + "\r\n:1\r\n";
                            out.write(reply.getBytes(StandardCharsets.US_ASCII));
                            out.flush();
                        }
                        case "CLUSTER" -> {
                            if (!authenticated) {
                                writeError(out, "NOAUTH Authentication required.");
                                continue;
                            }
                            String sub = args.size() > 1
                                    ? new String(args.get(1), StandardCharsets.US_ASCII)
                                            .toUpperCase(Locale.ROOT)
                                    : "";
                            if ("NODES".equals(sub)) {
                                String self1 = port() == peer1Port ? "myself,master" : "master";
                                String self2 = port() == peer2Port ? "myself,master" : "master";
                                String body = "0000000000000000000000000000000000000001 "
                                        + peer1Host + ":" + peer1Port + "@16379 " + self1
                                        + " - 0 0 1 connected 0-8191\n"
                                        + "0000000000000000000000000000000000000002 "
                                        + peer2Host + ":" + peer2Port + "@16380 " + self2
                                        + " - 0 0 2 connected 8192-16383\n";
                                writeBulk(out, body);
                            } else if ("SLOTS".equals(sub)) {
                                String reply = "*2\r\n"
                                        + "*3\r\n:0\r\n:8191\r\n*3\r\n$" + peer1Host.length()
                                        + "\r\n" + peer1Host + "\r\n:" + peer1Port
                                        + "\r\n$40\r\n0000000000000000000000000000000000000001\r\n"
                                        + "*3\r\n:8192\r\n:16383\r\n*3\r\n$" + peer2Host.length()
                                        + "\r\n" + peer2Host + "\r\n:" + peer2Port
                                        + "\r\n$40\r\n0000000000000000000000000000000000000002\r\n";
                                out.write(reply.getBytes(StandardCharsets.US_ASCII));
                                out.flush();
                            } else {
                                writeError(out, "ERR unknown subcommand '" + sub + "'");
                            }
                        }
                        case "SET" -> {
                            if (!authenticated) {
                                writeError(out, "NOAUTH Authentication required.");
                                continue;
                            }
                            store.put(new String(args.get(1), StandardCharsets.UTF_8),
                                    new String(args.get(2), StandardCharsets.UTF_8));
                            writeSimple(out, "OK");
                        }
                        case "GET" -> {
                            if (!authenticated) {
                                writeError(out, "NOAUTH Authentication required.");
                                continue;
                            }
                            String val = store.get(new String(args.get(1), StandardCharsets.UTF_8));
                            if (val == null) {
                                out.write("$-1\r\n".getBytes(StandardCharsets.US_ASCII));
                                out.flush();
                            } else {
                                writeBulk(out, val);
                            }
                        }
                        default -> writeError(out, "ERR unknown command '" + cmd + "'");
                    }
                    for (byte[] arg : args) {
                        java.util.Arrays.fill(arg, (byte) 0);
                    }
                }
            } catch (IOException ignored) {
                // client closed or handshake rejected
            }
        }

        private boolean checkAuth(String user, byte[] pw) {
            boolean ok = (expectedUser == null || expectedUser.equals(user))
                    && expectedPassword != null
                    && java.security.MessageDigest.isEqual(expectedPassword, pw);
            java.util.Arrays.fill(pw, (byte) 0);
            return ok;
        }

        private static List<byte[]> readCommand(InputStream in) throws IOException {
            int first = in.read();
            if (first < 0) {
                return null;
            }
            if (first != '*') {
                throw new IOException("expected '*', got " + (char) first);
            }
            int count = readCount(in);
            List<byte[]> args = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                int dollar = in.read();
                if (dollar != '$') {
                    throw new IOException("expected '$', got " + (char) dollar);
                }
                int len = readCount(in);
                byte[] data = in.readNBytes(len);
                if (data.length < len) {
                    throw new EOFException();
                }
                if (in.read() != '\r' || in.read() != '\n') {
                    throw new IOException("missing CRLF after bulk string");
                }
                args.add(data);
            }
            return args;
        }

        private static int readCount(InputStream in) throws IOException {
            String line = readLine(in);
            try {
                return Integer.parseInt(line);
            } catch (NumberFormatException e) {
                throw new IOException("not a length: " + line, e);
            }
        }

        private static String readLine(InputStream in) throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            while (true) {
                int b = in.read();
                if (b < 0) {
                    throw new EOFException();
                }
                if (b == '\r') {
                    int lf = in.read();
                    if (lf == '\n') {
                        return buf.toString(StandardCharsets.US_ASCII);
                    }
                    buf.write(b);
                    buf.write(lf);
                } else {
                    buf.write(b);
                }
            }
        }

        private static void writeSimple(OutputStream out, String msg) throws IOException {
            out.write(("+" + msg + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
        }

        private static void writeError(OutputStream out, String msg) throws IOException {
            out.write(("-" + msg + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
        }

        private static void writeBulk(OutputStream out, String text) throws IOException {
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
            out.write(("$" + bytes.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(bytes);
            out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
        }

        @Override
        public void close() throws IOException {
            if (expectedPassword != null) {
                java.util.Arrays.fill(expectedPassword, (byte) 0);
            }
            server.close();
        }
    }
}
