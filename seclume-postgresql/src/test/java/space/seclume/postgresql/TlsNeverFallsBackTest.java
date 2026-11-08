package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Never a silent fallback to a connection less safe than the one asked for -
 * every TLS mode against every way a server, or whoever sits in front of it,
 * can make TLS fail.
 *
 * <p>The servers: one that says no to TLS; one that says yes and then sends
 * bytes that are not TLS; one that hangs up in the middle of the handshake;
 * one that answers with a fatal alert; and three that finish the handshake
 * with a certificate that must not pass {@code verify-full} - self-signed and
 * untrusted, issued by a trusted CA for another host, issued by it and expired.
 *
 * <p>For every refusal: an {@link SQLException} of class 08, nothing of the
 * login on the wire in the clear - the startup message names the user and the
 * database - no second connection that tries again without TLS, the password
 * source never asked, and no secret left open. Over both TLS stacks.
 *
 * <p>The one case that does go on in the clear is the one that is documented
 * to: {@code tls=prefer} against a server that says it has no TLS. That one is
 * checked too - so that it stays the only one.
 */
@Isolated
@Timeout(300)
class TlsNeverFallsBackTest {

    private static final String STORE_PASSWORD = "fake-postgres";

    @TempDir
    static Path directory;
    private static SSLContext selfSigned;
    private static SSLContext otherHost;
    private static SSLContext expired;
    private static Path caPem;

    /** What the server does after the SSLRequest. */
    enum Server {
        NO_TLS, NOT_TLS, HANGS_UP, FATAL_ALERT, SELF_SIGNED, OTHER_HOST, EXPIRED;

        boolean handshakes() {
            return ordinal() >= SELF_SIGNED.ordinal();
        }
    }

    /** What the server saw. */
    record Seen(int connections, byte[] clear, boolean startupInTls) {
    }

    @BeforeAll
    static void certificates() throws Exception {
        // A CA, and from it a certificate for another host and one that expired.
        Path ca = directory.resolve("ca.p12");
        keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=fake-ca", "-ext", "bc:c", "-validity", "10", "-keystore", ca);
        caPem = directory.resolve("ca.pem");
        keytool("-exportcert", "-rfc", "-alias", "ca", "-keystore", ca, "-file", caPem);
        otherHost = issued(ca, "other", "san=dns:other.example,ip:127.0.0.2", "-validity", "5");
        expired = issued(ca, "expired", "san=ip:127.0.0.1", "-startdate", "-10d", "-validity", "2");
        Path own = directory.resolve("self.p12");
        keytool("-genkeypair", "-alias", "self", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=fake-postgres", "-ext", "san=ip:127.0.0.1", "-validity", "5",
                "-keystore", own);
        selfSigned = context(own);
    }

    /** A key for {@code alias}, signed by the CA in {@code ca}, as a server context. */
    private static SSLContext issued(Path ca, String alias, String san, String... validity)
            throws Exception {
        Path store = directory.resolve(alias + ".p12");
        keytool("-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=" + alias, "-validity", "5", "-keystore", store);
        Path request = directory.resolve(alias + ".csr");
        Path signed = directory.resolve(alias + ".pem");
        keytool("-certreq", "-alias", alias, "-keystore", store, "-file", request);
        List<Object> sign = new ArrayList<>(List.of("-gencert", "-alias", "ca", "-keystore", ca,
                "-infile", request, "-outfile", signed, "-rfc", "-ext", san));
        sign.addAll(List.of((Object[]) validity));
        keytool(sign.toArray());
        keytool("-importcert", "-noprompt", "-alias", "ca", "-keystore", store, "-file", caPem);
        keytool("-importcert", "-noprompt", "-alias", alias, "-keystore", store, "-file", signed);
        return context(store);
    }

    private static void keytool(Object... arguments) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        for (Object argument : arguments) {
            command.add(argument.toString());
        }
        command.addAll(List.of("-storetype", "PKCS12", "-storepass", STORE_PASSWORD));
        if (command.contains("-genkeypair")) {
            command.addAll(List.of("-keypass", STORE_PASSWORD));
        }
        Process keytool = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(keytool.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(keytool.waitFor(60, TimeUnit.SECONDS) && keytool.exitValue() == 0,
                "keytool " + command + ": " + output);
    }

    private static SSLContext context(Path store) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, STORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory factory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, STORE_PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(factory.getKeyManagers(), null, null);
        return context;
    }

    @Test
    void noModeFallsBackAndVerifyFullTakesNoCertificateItCannotCheck() throws Exception {
        List<String> wrong = new ArrayList<>();
        for (TlsStack stack : new TlsStack[] {TlsStack.SECLUME, TlsStack.JSSE}) {
            for (TlsMode mode : new TlsMode[] {TlsMode.PREFER, TlsMode.REQUIRE, TlsMode.VERIFY_FULL}) {
                for (Server server : Server.values()) {
                    String verdict = oneCase(stack, mode, server);
                    if (verdict != null) {
                        wrong.add(stack + " tls=" + mode + " against " + server + ": " + verdict);
                    }
                }
            }
        }
        assertEquals(List.of(), wrong);
    }

    /** Null if the case went as it must, or what went wrong. */
    private static String oneCase(TlsStack stack, TlsMode mode, Server server) throws Exception {
        boolean refusedExpected = !(server == Server.NO_TLS && mode == TlsMode.PREFER)
                && !(server.handshakes() && !mode.verifies());
        int[] asked = new int[1];
        long open = SecretScope.open();
        try (ServerSocket listener = new ServerSocket(0, 4, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Seen> seen = serve(listener, server);
            SQLException failure = null;
            try {
                TrustChoice.Choice trust = server == Server.OTHER_HOST || server == Server.EXPIRED
                        ? TrustChoice.of("jdbc:x://h/db?tlsRootCert=" + caPem, null) : null;
                PgSession session = trust == null
                        ? PgSession.open(settings(listener.getLocalPort(), mode, stack, asked))
                        : TrustChoice.using(trust, () -> PgSession.open(
                                settings(listener.getLocalPort(), mode, stack, asked)));
                session.close();
            } catch (SQLException e) {
                failure = e;
            }
            Seen what = seen.get(60, TimeUnit.SECONDS);
            if (SecretScope.open() != open) {
                return "a secret was left open";
            }
            if (!refusedExpected) {
                // The two that go on: in the clear only where tls=prefer was
                // told there is no TLS, and inside TLS where nothing is checked.
                if (server == Server.NO_TLS) {
                    return contains(what.clear(), "user\0app\0") ? null
                            : "prefer without TLS did not go on in the clear";
                }
                return what.startupInTls() ? null : "TLS that checks nothing did not go on: "
                        + failure;
            }
            if (failure == null) {
                return "connected";
            }
            if (failure.getSQLState() == null || !failure.getSQLState().startsWith("08")) {
                return "refused with SQLState " + failure.getSQLState() + ": " + failure;
            }
            if (contains(what.clear(), "user\0") || contains(what.clear(), "app\0")) {
                return "the startup message went out in the clear";
            }
            if (what.startupInTls()) {
                return "the startup message went to a server whose certificate failed";
            }
            if (what.connections() != 1) {
                return what.connections() + " connections - it tried again";
            }
            if (asked[0] != 0) {
                return "the password was read for a connection that was refused";
            }
            return null;
        }
    }

    /**
     * Accepts one connection and plays {@code server}, then waits a moment for
     * a second one: a client that tries again without TLS would make it.
     */
    private static CompletableFuture<Seen> serve(ServerSocket listener, Server server) {
        return CompletableFuture.supplyAsync(() -> {
            int connections = 0;
            ByteArrayOutputStream clear = new ByteArrayOutputStream();
            boolean startupInTls = false;
            try {
                listener.setSoTimeout(30_000);
                try (Socket plain = listener.accept()) {
                    connections++;
                    plain.setSoTimeout(10_000);
                    InputStream in = plain.getInputStream();
                    OutputStream out = plain.getOutputStream();
                    byte[] request = in.readNBytes(8);
                    if (request.length < 8 || request[4] != 0x04 || request[5] != (byte) 0xd2) {
                        clear.write(request);
                    } else {
                        startupInTls = play(server, plain, in, out, clear);
                    }
                }
                listener.setSoTimeout(700);
                while (true) {
                    try (Socket again = listener.accept()) {
                        connections++;
                        again.setSoTimeout(2_000);
                        clear.write(readSome(again.getInputStream()));
                    } catch (SocketTimeoutException none) {
                        break;
                    }
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return new Seen(connections, clear.toByteArray(), startupInTls);
        });
    }

    /** Whether the startup message arrived inside TLS. */
    private static boolean play(Server server, Socket plain, InputStream in, OutputStream out,
                                ByteArrayOutputStream clear) throws IOException {
        switch (server) {
            case NO_TLS -> {
                out.write('N');
                out.flush();
                plain.setSoTimeout(2_000);
                clear.write(readSome(in));
                return false;
            }
            case NOT_TLS -> {
                out.write('S');
                out.write("HTTP/1.1 400 Bad Request\r\n\r\nthis is not TLS at all"
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
                drain(in);
                return false;
            }
            case HANGS_UP -> {
                out.write('S');
                out.flush();
                in.readNBytes(5);
                return false;
            }
            case FATAL_ALERT -> {
                out.write('S');
                out.flush();
                in.readNBytes(5);
                // alert, TLS 1.2 record version, length 2: fatal, handshake_failure
                out.write(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28});
                out.flush();
                drain(in);
                return false;
            }
            default -> {
                out.write('S');
                out.flush();
                SSLContext context = switch (server) {
                    case SELF_SIGNED -> selfSigned;
                    case OTHER_HOST -> otherHost;
                    default -> expired;
                };
                SSLSocket tls = (SSLSocket) context.getSocketFactory()
                        .createSocket(plain, "127.0.0.1", plain.getPort(), true);
                tls.setUseClientMode(false);
                try {
                    tls.startHandshake();
                    InputStream inside = tls.getInputStream();
                    byte[] length = inside.readNBytes(4);
                    if (length.length < 4) {
                        return false;
                    }
                    // A startup message, then a refusal so that the client stops.
                    inside.readNBytes(java.nio.ByteBuffer.wrap(length).getInt() - 4);
                    byte[] error = "SFATAL\0C28000\0Mnot here\0\0".getBytes(StandardCharsets.US_ASCII);
                    OutputStream toClient = tls.getOutputStream();
                    toClient.write('E');
                    toClient.write(java.nio.ByteBuffer.allocate(4).putInt(4 + error.length).array());
                    toClient.write(error);
                    toClient.flush();
                    return true;
                } catch (IOException refusedByTheClient) {
                    return false;
                }
            }
        }
    }

    /** What arrives within two seconds, or until the client hangs up. */
    private static byte[] readSome(InputStream in) {
        ByteArrayOutputStream read = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        try {
            for (int n; (n = in.read(buffer)) > 0; ) {
                read.write(buffer, 0, n);
            }
        } catch (IOException timeoutOrReset) {
            // what came, came
        }
        return read.toByteArray();
    }

    private static void drain(InputStream in) {
        readSome(in);
    }

    private static boolean contains(byte[] haystack, String needle) {
        byte[] wanted = needle.getBytes(StandardCharsets.US_ASCII);
        outer:
        for (int i = 0; i + wanted.length <= haystack.length; i++) {
            for (int j = 0; j < wanted.length; j++) {
                if (haystack[i + j] != wanted[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static PgSession.Settings settings(int port, TlsMode mode, TlsStack stack, int[] asked) {
        SecretProvider password = new CallbackSecretProvider(64, target -> {
            asked[0]++;
            byte[] bytes = "not-the-password".getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
        return new PgSession.Settings("127.0.0.1", port, "app", "app", password, "seclume-test",
                10_000, HostList.of("127.0.0.1", port), ResultLimit.NONE, mode, stack);
    }

    @Test
    void theCaseThatGoesOnInTheClearIsOnlyPreferAgainstNoTls() throws Exception {
        // A guard on the guard: if NO_TLS ever stopped being let through under
        // prefer, the matrix above would report it, but this names the rule.
        assertFalse(TlsMode.PREFER.demands());
        assertTrue(TlsMode.REQUIRE.demands() && TlsMode.VERIFY_FULL.demands());
        assertTrue(TlsMode.VERIFY_FULL.verifies());
        assertFalse(TlsMode.REQUIRE.verifies() || TlsMode.PREFER.verifies());
        if (TlsMode.of("verify-ca") != TlsMode.VERIFY_FULL) {
            fail("verify-ca must check the host name too");
        }
    }
}
