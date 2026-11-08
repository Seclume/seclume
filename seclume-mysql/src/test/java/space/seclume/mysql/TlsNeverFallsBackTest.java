package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

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
import space.seclume.tck.HostileTls;
import space.seclume.tck.HostileTls.Behaviour;

/**
 * MySQL's way of saying yes to TLS is a capability bit in its greeting, and
 * the client's is a 32-byte SSL request in place of the login. Every TLS mode
 * against a server without the bit, and against one with it that then makes
 * TLS fail in each of the ways {@link HostileTls} does.
 *
 * <p>For every refusal: an {@link SQLException} of class 08, no login in the
 * clear - it names the user and carries the password's scramble - none inside
 * a TLS whose certificate failed, no second connection, the password source
 * never asked, and no secret left open. Over both TLS stacks. {@code prefer}
 * against a server without TLS goes on in the clear, as documented, and is
 * checked to.
 */
@Isolated
@Timeout(300)
class TlsNeverFallsBackTest {

    private static final byte[] SCRAMBLE = "abcdefghijklmnopqrst".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    static Path directory;
    private static HostileTls hostile;

    /** What the server saw. */
    record Seen(int connections, byte[] clear, byte[] insideTls) {
    }

    @BeforeAll
    static void certificates() throws Exception {
        hostile = HostileTls.create(directory);
    }

    @Test
    void noModeFallsBackAndVerifyFullTakesNoCertificateItCannotCheck() throws Exception {
        List<Behaviour> servers = new ArrayList<>();
        servers.add(null);
        servers.addAll(List.of(Behaviour.values()));
        List<String> wrong = new ArrayList<>();
        for (TlsStack stack : new TlsStack[] {TlsStack.SECLUME, TlsStack.JSSE}) {
            for (TlsMode mode : new TlsMode[] {TlsMode.PREFER, TlsMode.REQUIRE, TlsMode.VERIFY_FULL}) {
                for (Behaviour server : servers) {
                    String verdict = oneCase(stack, mode, server);
                    if (verdict != null) {
                        wrong.add(stack + " tls=" + mode + " against "
                                + (server == null ? "NO_TLS" : server) + ": " + verdict);
                    }
                }
            }
        }
        assertEquals(List.of(), wrong);
    }

    /** Null if the case went as it must, or what went wrong. */
    private static String oneCase(TlsStack stack, TlsMode mode, Behaviour behaviour)
            throws Exception {
        boolean goesOn = (behaviour == null && mode == TlsMode.PREFER)
                || (behaviour != null && behaviour.handshakes() && !mode.verifies());
        int[] asked = new int[1];
        long open = SecretScope.open();
        try (ServerSocket listener = new ServerSocket(0, 4, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Seen> seen = serve(listener, behaviour);
            SQLException failure = null;
            try {
                MySession.Settings settings = settings(listener.getLocalPort(), mode, stack, asked);
                MySession session = behaviour != null && behaviour.fromTrustedCa()
                        ? TrustChoice.using(TrustChoice.of("jdbc:x://h/db?tlsRootCert="
                                + hostile.caPem(), null), () -> MySession.open(settings))
                        : MySession.open(settings);
                session.close();
            } catch (SQLException e) {
                failure = e;
            }
            Seen what = seen.get(60, TimeUnit.SECONDS);
            if (SecretScope.open() != open) {
                return "a secret was left open";
            }
            if (goesOn) {
                if (behaviour == null) {
                    return HostileTls.contains(what.clear(), "app\0") ? null
                            : "prefer without TLS did not go on in the clear";
                }
                return what.insideTls() != null ? null
                        : "TLS that checks nothing did not go on: " + failure;
            }
            if (failure == null) {
                return "connected";
            }
            if (failure.getSQLState() == null || !failure.getSQLState().startsWith("08")) {
                return "refused with SQLState " + failure.getSQLState() + ": " + failure;
            }
            if (HostileTls.contains(what.clear(), "app\0")) {
                return "the login went out in the clear";
            }
            if (what.insideTls() != null) {
                return "the login went to a server whose certificate failed";
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
     * Greets with or without the SSL bit, takes the client's SSL request and
     * plays the behaviour - or records whatever the client sent in the clear
     * instead. Then waits a moment for a second connection.
     */
    private static CompletableFuture<Seen> serve(ServerSocket listener, Behaviour behaviour) {
        return CompletableFuture.supplyAsync(() -> {
            int connections = 0;
            ByteArrayOutputStream clear = new ByteArrayOutputStream();
            byte[] inside = null;
            try {
                listener.setSoTimeout(30_000);
                try (Socket plain = listener.accept()) {
                    connections++;
                    plain.setSoTimeout(10_000);
                    InputStream in = plain.getInputStream();
                    OutputStream out = plain.getOutputStream();
                    greet(out, behaviour != null);
                    if (behaviour == null) {
                        plain.setSoTimeout(2_000);
                        clear.write(HostileTls.readSome(in));
                    } else {
                        byte[] head = in.readNBytes(4);
                        int length = head.length < 4 ? 0
                                : (head[0] & 0xff) | (head[1] & 0xff) << 8 | (head[2] & 0xff) << 16;
                        byte[] answer = in.readNBytes(length);
                        int capabilities = answer.length < 4 ? 0 : (answer[0] & 0xff)
                                | (answer[1] & 0xff) << 8 | (answer[2] & 0xff) << 16
                                | (answer[3] & 0xff) << 24;
                        if (answer.length == 32 && MyCapabilities.has(capabilities, MyCapabilities.SSL)) {
                            inside = hostile.misbehave(behaviour, plain);
                        } else {
                            clear.write(head);
                            clear.write(answer);                  // a login in the clear
                        }
                    }
                }
                listener.setSoTimeout(700);
                while (true) {
                    try (Socket again = listener.accept()) {
                        connections++;
                        again.setSoTimeout(2_000);
                        greet(again.getOutputStream(), behaviour != null);
                        clear.write(HostileTls.readSome(again.getInputStream()));
                    } catch (SocketTimeoutException none) {
                        break;
                    }
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return new Seen(connections, clear.toByteArray(), inside);
        });
    }

    /** A MySQL 8.4 greeting, with or without the SSL capability. */
    private static void greet(OutputStream out, boolean ssl) throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(10);
        payload.writeBytes("8.4.0-fake\0".getBytes(StandardCharsets.US_ASCII));
        writeInt(payload, 7, 4);
        payload.write(SCRAMBLE, 0, 8);
        payload.write(0);
        int lower = MyCapabilities.PROTOCOL_41 | MyCapabilities.SECURE_CONNECTION
                | MyCapabilities.CONNECT_WITH_DB | MyCapabilities.TRANSACTIONS
                | (ssl ? MyCapabilities.SSL : 0);
        writeInt(payload, lower & 0xffff, 2);
        payload.write(45);
        writeInt(payload, 2, 2);
        int upper = MyCapabilities.PLUGIN_AUTH | MyCapabilities.PLUGIN_AUTH_LENENC_CLIENT_DATA
                | MyCapabilities.DEPRECATE_EOF | MyCapabilities.CONNECT_ATTRS
                | MyCapabilities.MULTI_RESULTS;
        writeInt(payload, upper >>> 16, 2);
        payload.write(21);
        payload.write(new byte[10]);
        payload.write(SCRAMBLE, 8, 12);
        payload.write(0);
        payload.writeBytes("caching_sha2_password\0".getBytes(StandardCharsets.US_ASCII));
        byte[] body = payload.toByteArray();
        out.write(body.length & 0xff);
        out.write((body.length >>> 8) & 0xff);
        out.write((body.length >>> 16) & 0xff);
        out.write(0);
        out.write(body);
        out.flush();
    }

    private static void writeInt(ByteArrayOutputStream out, long value, int length) {
        for (int i = 0; i < length; i++) {
            out.write((int) ((value >>> (8 * i)) & 0xff));
        }
    }

    private static MySession.Settings settings(int port, TlsMode mode, TlsStack stack, int[] asked) {
        SecretProvider password = new CallbackSecretProvider(64, target -> {
            asked[0]++;
            byte[] bytes = "not-the-password".getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
        return new MySession.Settings("127.0.0.1", port, "testdb", "app", password, "seclume",
                10_000, false, HostList.of("127.0.0.1", port), ResultLimit.NONE, mode, stack,
                null, true, java.util.Set.of(), false);
    }
}
