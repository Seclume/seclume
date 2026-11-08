package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
 * Oracle over TCPS: TLS from the first byte, before the listener sees a
 * CONNECT. {@code tls=require} and {@code tls=verify-full}, over both stacks,
 * against each way {@link HostileTls} breaks TLS - and under
 * {@code verify-full} each certificate it cannot check.
 *
 * <p>For every refusal: an {@link SQLException} of class 08, nothing in the
 * clear and nothing inside a TLS whose certificate failed - the CONNECT names
 * the service and the user - no second connection, the password never read,
 * no secret left open.
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

    @Test
    void tcpsNeverFallsBackAndVerifyFullTakesNoCertificateItCannotCheck() throws Exception {
        List<String> wrong = new ArrayList<>();
        for (TlsStack stack : new TlsStack[] {TlsStack.SECLUME, TlsStack.JSSE}) {
            for (TlsMode mode : new TlsMode[] {TlsMode.REQUIRE, TlsMode.VERIFY_FULL}) {
                for (Behaviour behaviour : Behaviour.values()) {
                    String verdict = oneCase(stack, mode, behaviour);
                    if (verdict != null) {
                        wrong.add(stack + " tls=" + mode + " against " + behaviour + ": " + verdict);
                    }
                }
            }
        }
        assertEquals(List.of(), wrong);
    }

    /** Null if the case went as it must, or what went wrong. */
    private static String oneCase(TlsStack stack, TlsMode mode, Behaviour behaviour)
            throws Exception {
        boolean goesOn = behaviour.handshakes() && !mode.verifies();
        int[] asked = new int[1];
        long open = SecretScope.open();
        try (ServerSocket listener = new ServerSocket(0, 4, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Seen> seen = serve(listener, behaviour);
            SQLException failure = null;
            try {
                OracleSession.Settings settings = settings(listener.getLocalPort(), mode, stack, asked);
                OracleSession session = behaviour.fromTrustedCa()
                        ? TrustChoice.using(TrustChoice.of("jdbc:x://h/db?tlsRootCert="
                                + hostile.caPem(), null), () -> OracleSession.open(settings))
                        : OracleSession.open(settings);
                session.close();
            } catch (SQLException e) {
                failure = e;
            }
            Seen what = seen.get(60, TimeUnit.SECONDS);
            if (hostile.lastPlaintext().length > 0) {
                return "the client went on in the clear: " + hostile.lastPlaintext().length + " bytes";
            }
            if (SecretScope.open() != open) {
                return "a secret was left open";
            }
            if (goesOn) {
                return what.insideTls() != null ? null
                        : "TLS that checks nothing did not go on: " + failure;
            }
            if (failure == null) {
                return "connected";
            }
            if (failure.getSQLState() == null || !failure.getSQLState().startsWith("08")) {
                return "refused with SQLState " + failure.getSQLState() + ": " + failure;
            }
            if (HostileTls.contains(what.clear(), "SERVICE_NAME")
                    || HostileTls.contains(what.clear(), "app")) {
                return "the CONNECT went out in the clear";
            }
            if (what.insideTls() != null) {
                return "the CONNECT went to a server whose certificate failed";
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

    private static CompletableFuture<Seen> serve(ServerSocket listener, Behaviour behaviour) {
        return CompletableFuture.supplyAsync(() -> {
            int connections = 0;
            ByteArrayOutputStream clear = new ByteArrayOutputStream();
            byte[] inside;
            try {
                listener.setSoTimeout(30_000);
                try (Socket plain = listener.accept()) {
                    connections++;
                    plain.setSoTimeout(10_000);
                    inside = hostile.misbehave(behaviour, plain);
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

    private static OracleSession.Settings settings(int port, TlsMode mode, TlsStack stack,
                                                   int[] asked) {
        SecretProvider password = new CallbackSecretProvider(64, target -> {
            asked[0]++;
            byte[] bytes = "not-the-password".getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
        return new OracleSession.Settings("127.0.0.1", port, "FREEPDB1", "app", password,
                10_000, HostList.of("127.0.0.1", port), ResultLimit.NONE, mode, stack);
    }
}
