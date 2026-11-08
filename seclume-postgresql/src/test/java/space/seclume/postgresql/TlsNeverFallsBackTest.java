package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
 * Never a silent fallback to a connection less safe than the one asked for -
 * every TLS mode against every way a server, or whoever sits in front of it,
 * can make TLS fail: it says it has none, or it says yes and then does one of
 * the things {@link HostileTls} does.
 *
 * <p>For every refusal: an {@link SQLException} of class 08, nothing of the
 * login on the wire in the clear - the startup message names the user and the
 * database - none inside a TLS whose certificate failed, no second connection
 * that tries again without TLS, the password source never asked, and no
 * secret left open. Over both TLS stacks.
 *
 * <p>The one case that goes on in the clear is the one that is documented to:
 * {@code tls=prefer} against a server that says it has no TLS. That one is
 * checked too - so that it stays the only one.
 */
@Isolated
@Timeout(300)
class TlsNeverFallsBackTest {

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

    /** Null for a server without TLS, then every way to fail after saying yes. */
    static List<Behaviour> servers() {
        List<Behaviour> servers = new ArrayList<>();
        servers.add(null);
        servers.addAll(List.of(Behaviour.values()));
        return servers;
    }

    @Test
    void noModeFallsBackAndVerifyFullTakesNoCertificateItCannotCheck() throws Exception {
        List<String> wrong = new ArrayList<>();
        for (TlsStack stack : new TlsStack[] {TlsStack.SECLUME, TlsStack.JSSE}) {
            for (TlsMode mode : new TlsMode[] {TlsMode.PREFER, TlsMode.REQUIRE, TlsMode.VERIFY_FULL}) {
                for (Behaviour server : servers()) {
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
                PgSession.Settings settings = settings(listener.getLocalPort(), mode, stack, asked);
                PgSession session = behaviour != null && behaviour.fromTrustedCa()
                        ? TrustChoice.using(TrustChoice.of("jdbc:x://h/db?tlsRootCert="
                                + hostile.caPem(), null), () -> PgSession.open(settings))
                        : PgSession.open(settings);
                session.close();
            } catch (SQLException e) {
                failure = e;
            }
            Seen what = seen.get(60, TimeUnit.SECONDS);
            if (SecretScope.open() != open) {
                return "a secret was left open";
            }
            if (goesOn) {
                // In the clear only where tls=prefer was told there is no
                // TLS; inside TLS where nothing is checked.
                if (behaviour == null) {
                    return HostileTls.contains(what.clear(), "user\0app\0") ? null
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
            if (HostileTls.contains(what.clear(), "user\0")
                    || HostileTls.contains(what.clear(), "app\0")) {
                return "the startup message went out in the clear";
            }
            if (what.insideTls() != null) {
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
     * Accepts one connection and plays the server, then waits a moment for a
     * second one: a client that tries again without TLS would make it.
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
                    byte[] request = in.readNBytes(8);
                    if (request.length < 8 || request[4] != 0x04 || request[5] != (byte) 0xd2) {
                        clear.write(request);                     // not an SSLRequest
                    } else if (behaviour == null) {
                        out.write('N');
                        out.flush();
                        plain.setSoTimeout(2_000);
                        clear.write(HostileTls.readSome(in));
                    } else {
                        out.write('S');
                        out.flush();
                        inside = hostile.misbehave(behaviour, plain);
                    }
                }
                listener.setSoTimeout(700);
                while (true) {
                    try (Socket again = listener.accept()) {
                        connections++;
                        again.setSoTimeout(2_000);
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
    void whatTheModesPromise() throws Exception {
        // The matrix above relies on these; a mode that changed its meaning
        // would change what it checks.
        assertFalse(TlsMode.PREFER.demands());
        assertTrue(TlsMode.REQUIRE.demands() && TlsMode.VERIFY_FULL.demands());
        assertTrue(TlsMode.VERIFY_FULL.verifies());
        assertFalse(TlsMode.REQUIRE.verifies() || TlsMode.PREFER.verifies());
        assertEquals(TlsMode.VERIFY_FULL, TlsMode.of("verify-ca"), "verify-ca checks the host too");
    }
}
