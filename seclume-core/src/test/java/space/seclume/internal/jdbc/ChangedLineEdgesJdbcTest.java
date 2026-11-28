package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * The edges of this release's new and changed lines in internal.jdbc, found
 * by the mutation check on changed lines once its every shard ran. Isolated:
 * two of them listen to a logger and reset a once-per-process warning.
 */
@Isolated
class ChangedLineEdgesJdbcTest {

    /** Host names and ports at the ends of what is one, and what an error says. */
    @Test
    void aHostAndAPortAreCheckedAtTheirEnds() {
        assertDoesNotThrow(() -> new HostList.Host("db", 1));
        assertDoesNotThrow(() -> new HostList.Host("db", 65535));
        assertThrows(IllegalArgumentException.class, () -> new HostList.Host("db", 0));
        assertThrows(IllegalArgumentException.class, () -> new HostList.Host("db", 65536));
        assertDoesNotThrow(() -> new HostList.Host("a".repeat(253), 5432));
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> new HostList.Host("a".repeat(254), 5432)).getMessage().endsWith("too long"));
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> new HostList.Host("", 5432)).getMessage().endsWith("empty"));
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> new HostList.Host(null, 5432)).getMessage().endsWith("none"));
        assertDoesNotThrow(() -> new HostList.Host("azAZ09.-_", 5432));
        for (String wrong : new String[] {"a`b", "a{b", "a@b", "a[b", "a/b", "a b"}) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> new HostList.Host(wrong, 5432), wrong);
            assertTrue(refused.getMessage().contains("character 2 is not"), refused.getMessage());
        }
    }

    /** patroniHosts ranges at their ends: /0 and /32 are ranges, /33 and a bare /24 are not. */
    @Test
    void patroniHostRangesAtTheirEnds() {
        assertDoesNotThrow(() -> PatroniTopology.Range.of("10.0.0.0/0"));
        assertDoesNotThrow(() -> PatroniTopology.Range.of("10.0.0.1/32"));
        assertDoesNotThrow(() -> PatroniTopology.Range.of("::1/128"));
        assertThrows(IllegalArgumentException.class, () -> PatroniTopology.Range.of("10.0.0.0/33"));
        assertThrows(IllegalArgumentException.class, () -> PatroniTopology.Range.of("10.0.0.0/-1"));
        IllegalArgumentException bare = assertThrows(IllegalArgumentException.class,
                () -> PatroniTopology.Range.of("/24"));
        assertTrue(bare.getMessage().contains("no address range"), bare.getMessage());
        assertNotNull(PatroniTopology.Range.address("10.0.0.9"));
        assertNotNull(PatroniTopology.Range.address("::1"));
        assertNull(PatroniTopology.Range.address("db.example"));
        PatroniTopology.Range eight = PatroniTopology.Range.of("10.0.0.0/8");
        assertTrue(eight.contains(PatroniTopology.Range.address("10.1.2.3")));
        assertFalse(eight.contains(PatroniTopology.Range.address("11.0.0.1")));
        assertFalse(eight.contains(PatroniTopology.Range.address("::1")));
    }

    /** A cluster description 64 levels deep is read; one level more is refused. */
    @Test
    void anAnswerIsReadUpToSixtyFourLevels() {
        assertDoesNotThrow(() -> PatroniTopology.parse("[".repeat(64) + "]".repeat(64)));
        IllegalArgumentException deep = assertThrows(IllegalArgumentException.class,
                () -> PatroniTopology.parse("[".repeat(65) + "]".repeat(65)));
        assertTrue(deep.getMessage().contains("64 levels"), deep.getMessage());
    }

    /**
     * Once all three are noted nothing more is learnt; before that a
     * statement still counts - a reversible change and an impersonation do
     * not stop an irreversible one being noted, nor the other way round.
     */
    @Test
    void whatIsNotYetNotedStillCounts() {
        SessionState state = new SessionState();
        state.note("set app.tenant_id = 1");
        state.note("execute as user = 'guest'");
        assertTrue(state.changed() && state.impersonated());
        assertFalse(state.irreversible());
        state.note("alter session set nls_language = 'GERMAN'");
        assertTrue(state.irreversible(), "an irreversible change after an impersonation");
        SessionState other = new SessionState();
        other.note("alter session set nls_language = 'GERMAN'");
        assertTrue(other.changed() && other.irreversible());
        other.note("execute as user = 'guest'");
        assertTrue(other.impersonated(), "an impersonation after an irreversible change");
    }

    /** A weakened TLS mode is said once per mode, saying what it gives up; verify-full says nothing. */
    @Test
    void aWeakenedTlsModeIsSaidOnceSayingWhatItGivesUp() throws Exception {
        java.lang.reflect.Field said = TlsMode.class.getDeclaredField("WEAKENED_SAID");
        said.setAccessible(true);
        ((java.util.Set<?>) said.get(null)).clear();
        List<String> warned = listen("space.seclume", () -> {
            TlsMode.of("verify-full");
            TlsMode.of("off");
            TlsMode.of("off");
            TlsMode.of("prefer");
        });
        assertEquals(2, warned.size(), warned.toString());
        assertTrue(warned.get(0).contains("no encryption"), warned.get(0));
        assertTrue(warned.get(1).contains("certificate is not checked"), warned.get(1));
    }

    /** Patroni asked over plain http is warned of, once per endpoint. */
    @Test
    void patroniOverPlainHttpIsWarnedOf() throws Exception {
        java.lang.reflect.Field said = PatroniTopology.class.getDeclaredField("PLAIN_WARNED");
        said.setAccessible(true);
        ((java.util.Set<?>) said.get(null)).clear();
        List<String> warned = listen(PatroniTopology.class.getName(), () ->
                PatroniTopology.of("http://patroni.invalid:8008", List.of("patroni.invalid")));
        assertEquals(1, warned.size(), "the first time it was not said: " + warned);
        assertTrue(warned.get(0).contains("plain http"), warned.get(0));
        assertTrue(listen(PatroniTopology.class.getName(), () -> PatroniTopology.of(
                "http://patroni.invalid:8008", List.of("patroni.invalid"))).isEmpty(),
                "it was said twice");
        ((java.util.Set<?>) said.get(null)).clear();
        assertTrue(listen(PatroniTopology.class.getName(), () -> PatroniTopology.of(
                "https://patroni.invalid:8008", List.of("patroni.invalid"))).isEmpty(),
                "https was warned of as plain http");
    }

    private interface Action {
        void run() throws Exception;
    }

    /** The messages logged at WARNING to {@code name} while {@code action} runs. */
    private static List<String> listen(String name, Action action) throws Exception {
        List<String> warned = new CopyOnWriteArrayList<>();
        Logger logger = Logger.getLogger(name);
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel() == java.util.logging.Level.WARNING) {
                    warned.add(record.getMessage());
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(handler);
        try {
            action.run();
        } finally {
            logger.removeHandler(handler);
        }
        return warned;
    }
}
