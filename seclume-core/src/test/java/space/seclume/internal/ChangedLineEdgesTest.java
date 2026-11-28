package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The edges of this release's new and changed lines in the internal package,
 * each to the character or the nanosecond where a test can tell: found by the
 * mutation check on changed lines once its every shard ran.
 */
class ChangedLineEdgesTest {

    /** A URL's password is hidden at the edges of each rule - exact strings, no more and no less. */
    @Test
    void passwordsAreHiddenAtTheEdgesOfTheRules() {
        // A // in quotes before the authority's: the authority after it is read too.
        assertEquals("jdbc:foo:\"q//q\"//user:?@host/db",
                JdbcUrl.redact("jdbc:foo:\"q//q\"//user:topsecret@host/db"));
        // A ) outside any ( leaves the next ( ... ) a key-value group: , ends a value there.
        assertEquals("jdbc:x:)//(password=?,user=?)",
                JdbcUrl.redact("jdbc:x:)//(password=p1,user=u)"));
        // A setting with no name: its value is hidden as any other.
        assertEquals("jdbc:mysql://h/db?=?&user=?", JdbcUrl.redact("jdbc:mysql://h/db?=lonely&user=u"));
        // After a closed ( ... ) the settings are outside again: a , is the value's.
        assertEquals("jdbc:sqlserver://h;(a=?);password=?;x=?",
                JdbcUrl.redact("jdbc:sqlserver://h;(a=b);password=se,cret;x=1"));
        assertEquals("jdbc:mysql://(host=?)/db;password=?",
                JdbcUrl.redact("jdbc:mysql://(host=h)/db;password=se,cret"));
    }

    /** Control characters escaped at the edges of their ranges; a clean text at the limit is itself. */
    @Test
    void serverTextIsEscapedAtTheEdgesOfTheControlRanges() {
        assertEquals("a\\x1f \\x7f\\x80\\x9f \tz",
                ServerText.printable("a\u001f \u007f\u0080\u009f \tz"));
        String limit = "a".repeat(ServerText.MAX);
        assertSame(limit, ServerText.printable(limit), "a clean text at the limit was copied");
        String cut = ServerText.printable("\u0001".repeat(3000));
        assertEquals(ServerText.MAX + "... (cut)".length(), cut.length());
        assertTrue(cut.endsWith("... (cut)"), cut);
        // One character in front: the last escape crosses the limit and is cut to it.
        assertEquals(ServerText.MAX + "... (cut)".length(),
                ServerText.printable("a" + "\u0001".repeat(3000)).length());
        // Each control range's ends alone - a text that is nothing else is escaped too.
        assertEquals("\\x80", ServerText.printable("\u0080"));
        assertEquals("\\x9f", ServerText.printable("\u009f"));
        assertEquals("\\x1f", ServerText.printable("\u001f"));
        assertEquals("\\x7f", ServerText.printable("\u007f"));
    }

    /** Padding is two '=' at most: a third is a character that is not base64. */
    @Test
    void base64PaddingIsTwoAtMostAndAnErrorNamesTheAlphabet() {
        IllegalArgumentException three = assertThrows(IllegalArgumentException.class,
                () -> Base64Text.decode("QQ==="));
        assertEquals("base64 of 3 characters and 2 padding is not whole", three.getMessage());
        IllegalArgumentException url = assertThrows(IllegalArgumentException.class,
                () -> Base64Text.decodeUrl("QQ!A"));
        assertTrue(url.getMessage().startsWith("not a base64url character"), url.getMessage());
        IllegalArgumentException plain = assertThrows(IllegalArgumentException.class,
                () -> Base64Text.decode("QQ!A"));
        assertTrue(plain.getMessage().startsWith("not a base64 character"), plain.getMessage());
    }

    /** Milliseconds left round up; the saturation point is exact. */
    @Test
    void deadlinesRoundUpAndSaturateExactly() {
        long left = Deadlines.remainingMillis(System.nanoTime() + 1_500_000);
        assertTrue(left >= 1 && left <= 2, "1.5 ms left was " + left + " ms");
        long last = Deadlines.FOREVER_NANOS / 1_000_000;
        assertEquals(last * 1_000_000, Deadlines.toNanos(last), "the last exact value");
        assertEquals(Deadlines.FOREVER_NANOS, Deadlines.toNanos(last + 1));
        assertEquals(0, Deadlines.toNanos(0));
        assertEquals(1_000_000, Deadlines.toNanos(1));
    }

    /** Which hosts a credential may go to: a literal seed is no domain, a two-label one no wildcard. */
    @Test
    void seedDomainsAdmitOnlyWhatTheSeedsCover() {
        assertTrue(SeedDomains.admits("node2.db.example.org", List.of("node1.db.example.org"),
                List.of()));
        assertFalse(SeedDomains.admits("evil.0.0.1", List.of("10.0.0.1"), List.of()),
                "an address literal was taken for a domain");
        assertFalse(SeedDomains.admits("evil.example", List.of("db.example"), List.of()),
                "a two-label seed was taken for a domain");
        assertFalse(SeedDomains.admits("a.example.com", List.of(".example.com"), List.of()),
                "a seed that starts with a dot is no host");
        assertFalse(SeedDomains.admits("x.1", List.of("fe80::1"), List.of()));
        assertEquals(List.of("h"), SeedDomains.hostsOf(List.of("://h:1")));
        assertEquals(List.of("db"), SeedDomains.hostsOf(List.of("mongodb://db:27017")));
        assertEquals(List.of("::1"), SeedDomains.hostsOf(List.of("[::1]:27017")));
        assertEquals(List.of(":5432"), SeedDomains.hostsOf(List.of(":5432")),
                "a port alone stays what it is - it matches no host");
    }

    /** A setting with no name is one: its value is not taken for part of a name. */
    @Test
    void aSettingWithNoNameKeepsItsValue() {
        JdbcUrl.Parsed parsed = JdbcUrl.parse("jdbc:seclume:postgresql://h/db?=x&user=u",
                new java.util.Properties(), "jdbc:seclume:postgresql:", 5432);
        assertEquals("x", parsed.options().get(""), parsed.options().toString());
        assertFalse(parsed.options().containsKey("=x"), parsed.options().toString());
    }

    /**
     * A secret source that takes the connection and then says nothing is
     * given up on after the timeout - not after the whole budget, three
     * times as long.
     */
    @Test
    void aSilentSecretSourceIsGivenUpOnAfterItsTimeout() throws Exception {
        try (java.net.ServerSocket silent = new java.net.ServerSocket(0, 4,
                java.net.InetAddress.getLoopbackAddress())) {
            Thread.ofVirtual().start(() -> {
                try (java.net.Socket client = silent.accept()) {
                    client.setTcpNoDelay(true);                  // and then nothing
                    Thread.sleep(30_000);
                } catch (Exception gone) {
                    // the client gave up
                }
            });
            long started = System.nanoTime();
            assertThrows(IOException.class, () -> SecretFetch.send("127.0.0.1",
                    silent.getLocalPort(), false, 1000, "GET", "/v1/secret", Map.of(), List.of(),
                    null, null));
            long took = (System.nanoTime() - started) / 1_000_000;
            assertTrue(took < 2_500, "a silent source held the fetch for " + took + " ms");
        }
    }

    /** A NUL anywhere in a NUL-terminated field is refused, at its very first character too. */
    @Test
    void aNulAtTheStartOfACStringIsRefused() {
        WireBuffer buffer = new WireBuffer(64);
        assertThrows(IllegalArgumentException.class, () -> buffer.putCString("\0abc"));
        assertThrows(IllegalArgumentException.class, () -> buffer.putCString("ab\0c"));
    }

    /**
     * send() refuses an unchecked server off this machine before it connects:
     * 192.0.2.1 (TEST-NET-1) is not answered, so a connect would wait out its
     * timeout and fail otherwise.
     */
    @Test
    void sendRefusesAnUncheckedServerOffThisMachineBeforeConnecting() {
        long started = System.nanoTime();
        IOException refused = assertThrows(IOException.class, () -> SecretFetch.send("192.0.2.1",
                443, false, 10_000, "GET", "/v1/secret", Map.of(), List.of(), null, null));
        assertTrue(refused.getMessage().contains("refused off this machine"), refused.getMessage());
        assertTrue(System.nanoTime() - started < 5_000_000_000L, "it tried to connect first");
    }
}
