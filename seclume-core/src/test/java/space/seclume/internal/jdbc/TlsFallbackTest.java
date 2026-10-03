package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.tls.TlsVersionRefused;

/** tlsStack=auto: when the JDK's stack is tried, and when it is not. */
@Isolated // the remembered servers are process-wide
class TlsFallbackTest {

    private final List<TlsStack> tried = new ArrayList<>();

    @BeforeEach
    @AfterEach
    void forget() {
        TlsFallback.forget();
    }

    /** How a driver reports a refused handshake: wrapped, as the connect's cause. */
    private static SQLException refused() {
        return new SQLNonTransientConnectionException("TLS to db:5432 failed", "08001",
                new TlsVersionRefused(new EOFException("the server closed the connection")));
    }

    private TlsFallback.Attempt<String> refusingOwnStack() {
        return stack -> {
            tried.add(stack);
            if (stack == TlsStack.SECLUME) {
                throw refused();
            }
            return "connected on " + stack;
        };
    }

    @Test
    void aServerWithoutTls13IsReachedOnJsse() throws SQLException {
        assertEquals("connected on JSSE",
                TlsFallback.connect(TlsStack.AUTO, false, "db", 5432, refusingOwnStack()));
        assertEquals(List.of(TlsStack.SECLUME, TlsStack.JSSE), tried);
    }

    @Test
    void aServerThatSpeaksItStaysOnTheOwnStack() throws SQLException {
        assertEquals("ok", TlsFallback.connect(TlsStack.AUTO, false, "db", 5432, stack -> {
            tried.add(stack);
            return "ok";
        }));
        assertEquals(List.of(TlsStack.SECLUME), tried);
    }

    /** The second connection to the same server does not ask again - a pool opens many. */
    @Test
    void theServerIsRememberedNotProbedEachTime() throws SQLException {
        TlsFallback.connect(TlsStack.AUTO, false, "db", 5432, refusingOwnStack());
        tried.clear();
        TlsFallback.connect(TlsStack.AUTO, false, "db", 5432, refusingOwnStack());
        assertEquals(List.of(TlsStack.JSSE), tried);
        // Another port is another server.
        tried.clear();
        TlsFallback.connect(TlsStack.AUTO, false, "db", 5433, refusingOwnStack());
        assertEquals(List.of(TlsStack.SECLUME, TlsStack.JSSE), tried);
    }

    /** Wrong password, untrusted certificate, unreachable host: no second stack. */
    @Test
    void anyOtherFailureIsNotRetried() {
        SQLException wrongPassword = new SQLException("password authentication failed", "28P01");
        SQLException thrown = assertThrows(SQLException.class,
                () -> TlsFallback.connect(TlsStack.AUTO, false, "db", 5432, stack -> {
                    tried.add(stack);
                    throw wrongPassword;
                }));
        assertSame(wrongPassword, thrown);
        assertEquals(List.of(TlsStack.SECLUME), tried);
    }

    /** tlsStack=seclume and tlsStack=jsse mean exactly that. */
    @Test
    void anExplicitStackIsNeverChanged() {
        assertThrows(SQLException.class,
                () -> TlsFallback.connect(TlsStack.SECLUME, false, "db", 5432, refusingOwnStack()));
        assertEquals(List.of(TlsStack.SECLUME), tried);
        tried.clear();
        assertThrows(SQLException.class, () -> TlsFallback.connect(TlsStack.JSSE, false, "db",
                5432, stack -> {
                    tried.add(stack);
                    throw refused();
                }));
        assertEquals(List.of(TlsStack.JSSE), tried);
    }

    /** A client key lives on the own stack only, so there is nothing to fall back to. */
    @Test
    void aClientCertificateKeepsTheOwnStack() {
        assertThrows(SQLException.class,
                () -> TlsFallback.connect(TlsStack.AUTO, true, "db", 5432, refusingOwnStack()));
        assertEquals(List.of(TlsStack.SECLUME), tried);
    }

    /** When JSSE fails as well, both failures are in what is thrown. */
    @Test
    void aFailedFallbackCarriesTheFirstFailure() {
        SQLException second = new SQLException("JSSE failed too", "08001");
        SQLException thrown = assertThrows(SQLException.class,
                () -> TlsFallback.connect(TlsStack.AUTO, false, "db", 5432, stack -> {
                    if (stack == TlsStack.SECLUME) {
                        throw refused();
                    }
                    throw second;
                }));
        assertSame(second, thrown);
        assertTrue(TlsFallbackProbe.wouldFallBack(thrown.getSuppressed()[0]));
    }

    @Test
    void autoIsTheDefaultAndEveryNameParses() throws SQLException {
        assertEquals(TlsStack.AUTO, TlsStack.of(null));
        assertEquals(TlsStack.AUTO, TlsStack.of(""));
        assertEquals(TlsStack.AUTO, TlsStack.of("AUTO"));
        assertEquals(TlsStack.AUTO, TlsStack.of("default"));
        assertEquals(TlsStack.JSSE, TlsStack.of("jsse"));
        assertEquals(TlsStack.JSSE, TlsStack.of("jdk"));
        assertEquals(TlsStack.SECLUME, TlsStack.of("seclume"));
        assertThrows(SQLException.class, () -> TlsStack.of("openssl"));
    }
}
