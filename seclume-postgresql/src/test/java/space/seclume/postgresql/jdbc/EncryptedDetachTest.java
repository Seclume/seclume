package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.TlsLayer;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.postgresql.PgSession;
import space.seclume.secret.SecretProviders;
import space.seclume.tck.TestHosts;

/**
 * What an encrypted stream carries when it is handed on - and what it refuses
 * to carry.
 *
 * <p>{@code detach()} used to refuse every encrypted session, for a reason
 * that is right about one TLS stack and wrong about the other. An
 * {@code SSLEngine} does not hand out a traffic secret or a record sequence
 * number - no method of {@code SSLSession} is named for either, by design -
 * so on the JDK's stack there is nothing that could go with the stream and
 * the refusal stays. On seclume's own stack the encryption is ours, so it can
 * go along: {@code detach()} hands the layer out and {@code resume()} takes
 * it up, and the server is told nothing.
 *
 * <p><b>What this class is, and what it deliberately is not.</b> It pins the
 * seam: an encrypted session on the own stack hands its encryption over, a
 * session in the clear hands over nothing, and the JDK's stack still says no
 * and says why. The driver's part ends there. What a caller does with the
 * layer afterwards - hand it straight to another session, or write its state
 * down with {@code freeze} and take it up somewhere else with {@code thaw} -
 * is the caller's business, and it is not this library's.
 */
@Timeout(120)
class EncryptedDetachTest {

    private static final int PORT = Integer.getInteger("seclume.pgtls.port", 5433);

    private static String host() {
        return System.getProperty("seclume.pgtls.host", TestHosts.database());
    }

    private static Path fixture() {
        Path secret = null;
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                secret = candidate.toAbsolutePath().normalize();
                break;
            }
        }
        Assumptions.assumeTrue(secret != null, "no TLS server configured");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host(), PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no TLS server on " + host() + ":" + PORT);
        }
        return secret;
    }

    private static PgSession.Settings settings(Path secret, TlsMode mode, TlsStack stack)
            throws SQLException {
        return new PgSession.Settings(host(), PORT, "seclume_test", "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", secret.toString())),
                "seclume", 5_000, HostList.of(host(), PORT), ResultLimit.NONE, mode, stack);
    }

    /**
     * The own stack hands its encryption out, and the socket stays open.
     *
     * <p>Both halves matter. A hand-over that closed the connection would be
     * a close with extra steps; the point is that the peer is told nothing at
     * all, so the transport is still open afterwards and the server still
     * believes it has a client.
     *
     * <p><b>And it stops there, deliberately.</b> That a session then carries
     * on under the new object - the same backend answering after the
     * hand-over, records continuing with the same keys and counters - is not
     * asserted here. This library provides the seam; demonstrating what can
     * be built on it is somebody else's test, in somebody else's repository.
     */
    @Test
    void theOwnStackHandsItsEncryptionOver() throws Exception {
        Path secret = fixture();
        PgSession.Detached detached;
        String description;
        try (PgSession session = PgSession.open(settings(secret, TlsMode.REQUIRE,
                TlsStack.SECLUME))) {
            description = session.tlsDescription();
            assertTrue(description != null && description.endsWith(" (seclume)"),
                    "this test is about our own stack; it got: " + description);
            assertNotNull(session.askOneValue("select 1"));
            detached = session.detach();
        }

        TlsLayer carried = detached.tls();
        assertNotNull(carried, "an encrypted stream was handed over without its encryption");
        assertTrue(carried.movable(),
                "the layer handed out is not the one whose state can travel");
        assertTrue(detached.stream().isOpen(),
                "the hand-over closed the socket, which is the one thing it must not do");
        System.err.println("[detach] " + description + " -> layer handed over, socket still open");
        detached.stream().close();
    }

    /**
     * The other side of the seam takes one back.
     *
     * <p>Wiring, not a demonstration: that {@code resume} accepts the layer
     * and puts it underneath the channel, so the parameter is reachable and
     * connected. Whether a session survives being handed over is a different
     * claim and is not made here.
     */
    @Test
    void resumeTakesALayerBack() throws Exception {
        Path secret = fixture();
        PgSession.Detached detached;
        try (PgSession session = PgSession.open(settings(secret, TlsMode.REQUIRE,
                TlsStack.SECLUME))) {
            detached = session.detach();
        }
        try (PgSession resumed = PgSession.resume(detached.stream(), detached.parameters(),
                detached.backendProcessId(), detached.backendSecretKey(), detached.tls())) {
            assertNotNull(resumed.tlsDescription(),
                    "the layer was handed in and the session reports no encryption");
            assertTrue(resumed.tlsDescription().endsWith(" (seclume)"),
                    "a different layer arrived underneath: " + resumed.tlsDescription());
        }
    }

    /**
     * And the refusal that stays, with its reason in the message.
     *
     * <p>Asserted rather than assumed, because it is the argument the whole
     * own TLS stack was written on.
     */
    @Test
    void theJdkStackStillRefuses() throws Exception {
        Path secret = fixture();
        try (PgSession session = PgSession.open(settings(secret, TlsMode.REQUIRE,
                TlsStack.JSSE))) {
            String tls = session.tlsDescription();
            assertTrue(tls != null && !tls.endsWith(" (seclume)"),
                    "this test is about the JDK's stack; it got: " + tls);
            SQLException refused = assertThrows(SQLException.class, session::detach);
            assertEquals("0A000", refused.getSQLState());
            assertTrue(refused.getMessage().contains("SSLEngine"),
                    "the refusal should say why: " + refused.getMessage());
            System.err.println("[detach] jdk stack: " + refused.getMessage());
        }
    }

    /** A stream in the clear carries no encryption, because there is none. */
    @Test
    void aStreamInTheClearCarriesNothing() throws Exception {
        Path secret = fixture();
        PgSession.Detached detached;
        try (PgSession session = PgSession.open(settings(secret, TlsMode.OFF,
                TlsStack.SECLUME))) {
            Assumptions.assumeTrue(session.tlsDescription() == null,
                    "this server insists on TLS, so there is no plain case to check");
            detached = session.detach();
        }
        assertNull(detached.tls(), "a stream in the clear handed over a TLS layer");
        detached.stream().close();
    }
}
