package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.postgresql.PgSession;
import space.seclume.secret.SecretProviders;
import space.seclume.tck.TestHosts;

/**
 * The default stack against real servers: one with TLS 1.3, and one held to
 * TLS 1.2 by {@code ssl_max_protocol_version} - what SQL Server on TDS 7.4 and
 * Oracle 19c are. Both are reached on seclume's own stack; the JDK's only when
 * asked for by name.
 *
 * <p>The TLS 1.2 server is {@code seclume.pgtls12.host}/{@code .port}
 * (default port 5439), the TLS 1.3 one the usual {@code seclume.pgtls.*}.
 * Without them the tests are skipped.
 */
@Isolated
@Timeout(120)
class LocalTlsStackAutoTest {

    private static final int TLS13_PORT = Integer.getInteger("seclume.pgtls.port", 5433);
    private static final int TLS12_PORT = Integer.getInteger("seclume.pgtls12.port", 5439);

    private static String tls13Host() {
        return System.getProperty("seclume.pgtls.host", TestHosts.database());
    }

    private static String tls12Host() {
        return System.getProperty("seclume.pgtls12.host", TestHosts.database());
    }

    private static Path secret() {
        for (Path candidate : List.of(Path.of(".local-pgtls-password"),
                Path.of("..", ".local-pgtls-password"))) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.abort("no TLS server configured");
        return null;
    }

    private static void reachable(String host, int port) {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no TLS server on " + host + ":" + port);
        }
    }

    private static PgSession.Settings settings(String host, int port, TlsStack stack)
            throws SQLException {
        return new PgSession.Settings(host, port, "seclume_test", "seclume_test",
                SecretProviders.of(Map.of("provider", "file", "path", secret().toString())),
                "seclume", 5_000, HostList.of(host, port), ResultLimit.NONE, TlsMode.REQUIRE,
                stack);
    }

    @Test
    void autoIsTheDefault() throws SQLException {
        assertEquals("auto", new SeclumeDataSource().getTlsStack());
    }

    @Test
    void aTls13ServerIsReachedOnSeclumesStack() throws Exception {
        reachable(tls13Host(), TLS13_PORT);
        try (PgSession session = PgSession.open(settings(tls13Host(), TLS13_PORT,
                TlsStack.AUTO))) {
            String tls = session.tlsDescription();
            assertTrue(tls.startsWith("TLSv1.3") && tls.endsWith(" (seclume)"), tls);
            assertEquals("42", session.askOneValue("select 42"));
        }
    }

    @Test
    void aTls12ServerIsReachedOnSeclumesStack() throws Exception {
        reachable(tls12Host(), TLS12_PORT);
        for (TlsStack stack : new TlsStack[] {TlsStack.AUTO, TlsStack.SECLUME}) {
            try (PgSession session = PgSession.open(settings(tls12Host(), TLS12_PORT, stack))) {
                String tls = session.tlsDescription();
                assertTrue(tls.startsWith("TLSv1.2 / TLS_ECDHE_") && tls.endsWith(" (seclume)"),
                        stack + ": " + tls);
                assertEquals("42", session.askOneValue("select 42"));
            }
        }
    }

    /** tlsStack=jsse: the JDK's TLS, only because it was asked for. */
    @Test
    void theJdksStackOnlyWhenAskedFor() throws Exception {
        reachable(tls12Host(), TLS12_PORT);
        try (PgSession session = PgSession.open(settings(tls12Host(), TLS12_PORT,
                TlsStack.JSSE))) {
            String tls = session.tlsDescription();
            assertTrue(tls.startsWith("TLSv1.2") && !tls.endsWith(" (seclume)"), tls);
        }
    }
}
