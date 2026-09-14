package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/** What the host list promises, without a server anywhere near it. */
class HostListTest {

    @Test
    void readsHostsWithAndWithoutPorts() {
        HostList list = HostList.parse("db1:5433, db2 ,db3:5434", 5432);
        assertEquals(List.of(new HostList.Host("db1", 5433),
                new HostList.Host("db2", 5432),
                new HostList.Host("db3", 5434)), list.hosts());
    }

    /** The colon inside an IPv6 address is not a port separator. */
    @Test
    void keepsIpv6Addresses() {
        HostList list = HostList.parse("[2001:db8::1],[2001:db8::2]:5433", 5432);
        assertEquals(List.of(new HostList.Host("[2001:db8::1]", 5432),
                new HostList.Host("[2001:db8::2]", 5433)), list.hosts());
    }

    @Test
    void refusesNonsenseEarly() {
        assertThrows(IllegalArgumentException.class, () -> HostList.parse("", 5432));
        assertThrows(IllegalArgumentException.class, () -> HostList.parse("db1:hello", 5432));
        assertThrows(IllegalArgumentException.class, () -> HostList.parse("db1:0", 5432));
        assertThrows(IllegalArgumentException.class, () -> HostList.parse("db1:70000", 5432));
    }

    @Test
    void takesTheNextServerWhenOneIsUnreachable() throws SQLException {
        HostList list = HostList.parse("dead:1,alive:2", 5432);
        List<String> tried = new ArrayList<>();
        String opened = list.open(host -> {
            tried.add(host.host());
            if ("dead".equals(host.host())) {
                throw new SQLException("nothing there", "08001");
            }
            return "connection to " + host.host();
        });
        assertEquals("connection to alive", opened);
        assertEquals(List.of("dead", "alive"), tried);
    }

    /** A dead first entry must not be paid for on every single connect. */
    @Test
    void asksTheServerThatAnsweredFirstNextTime() throws SQLException {
        HostList list = HostList.parse("dead:1,alive:2", 5432);
        HostList.Opener<String> opener = host -> {
            if ("dead".equals(host.host())) {
                throw new SQLException("nothing there", "08001");
            }
            return host.host();
        };
        assertEquals("alive", list.open(opener));

        List<String> tried = new ArrayList<>();
        list.open(host -> {
            tried.add(host.host());
            return host.host();
        });
        assertEquals(List.of("alive"), tried, "the dead one must not be asked again first");
    }

    /**
     * The one that matters: a wrong password is not a connection problem. Going
     * on to the next server would ask the same question again and collect a
     * failed login on every node of the list.
     */
    @Test
    void doesNotMoveOnAfterARejectedLogin() {
        HostList list = HostList.parse("one:1,two:2", 5432);
        List<String> tried = new ArrayList<>();
        SQLException thrown = assertThrows(SQLException.class, () -> list.open(host -> {
            tried.add(host.host());
            throw new SQLException("password authentication failed", "28P01");
        }));
        assertEquals("28P01", thrown.getSQLState());
        assertEquals(1, tried.size(), "only the first server may have been asked");
    }

    @Test
    void reportsEverythingItTriedWhenNothingAnswers() {
        HostList list = HostList.parse("one:1,two:2,three:3", 5432);
        SQLException thrown = assertThrows(SQLException.class,
                () -> list.open(host -> {
                    throw new SQLException("no route to " + host.host(), "08001");
                }));
        assertTrue(thrown.getMessage().contains("one:1"), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("three:3"), thrown.getMessage());
        assertEquals(2, countSuppressed(thrown.getCause()),
                "the other servers' answers have to be attached, not swallowed");
    }

    private static int countSuppressed(Throwable failure) {
        int count = 0;
        for (Throwable one = failure; one != null && one.getSuppressed().length > 0;
                one = one.getSuppressed()[0]) {
            count++;
        }
        return count;
    }

    @Test
    void aSingleHostGoesStraightThrough() throws SQLException {
        HostList list = HostList.of("only", 5432);
        Object token = new Object();
        assertSame(token, list.open(host -> token));
        assertEquals(1, list.size());
    }
}
