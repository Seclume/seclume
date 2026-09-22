package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Picking a server by what it is, not by what answers first.
 *
 * <p>No server here, on purpose. What a real cluster would add is a second
 * machine in a different state, and there is exactly one of each database on
 * this network - so the part that can be proven against them is that the
 * question is asked and understood (see the live tests per driver), and the
 * part that can be proven here is the choosing. A fake host list with three
 * servers of known roles says more about the rule than one real primary ever
 * could.
 */
class TargetServerTest {

    @Test
    void anUnknownRoleIsAcceptedByEveryTarget() {
        for (TargetServer target : TargetServer.values()) {
            assertTrue(target.accepts(ServerRole.UNKNOWN),
                    target + " refused a server that could not describe itself - which turns "
                    + "a working cluster into an outage over an unanswered question");
        }
    }

    @Test
    void aPrimaryIsNotASecondaryAndTheOtherWayAround() {
        assertTrue(TargetServer.PRIMARY.accepts(ServerRole.PRIMARY));
        assertFalse(TargetServer.PRIMARY.accepts(ServerRole.STANDBY));
        assertTrue(TargetServer.SECONDARY.accepts(ServerRole.STANDBY));
        assertFalse(TargetServer.SECONDARY.accepts(ServerRole.PRIMARY));
        assertTrue(TargetServer.ANY.accepts(ServerRole.PRIMARY));
        assertTrue(TargetServer.ANY.accepts(ServerRole.STANDBY));
    }

    /** A typo must not quietly mean "any server". */
    @Test
    void aSpellingItDoesNotKnowIsRefused() {
        assertSame(TargetServer.ANY, TargetServer.of(null));
        assertSame(TargetServer.ANY, TargetServer.of(""));
        assertSame(TargetServer.PRIMARY, TargetServer.of("Primary"));
        assertSame(TargetServer.SECONDARY, TargetServer.of("replica"));
        IllegalArgumentException wrong = assertThrows(IllegalArgumentException.class,
                () -> TargetServer.of("primry"));
        assertTrue(wrong.getMessage().contains("any, primary, secondary"),
                "the refusal should say what is allowed: " + wrong.getMessage());
    }

    /** Every answer the four databases actually give, read back. */
    @Test
    void theAnswersTheServersGiveAreUnderstood() {
        assertEquals(ServerRole.PRIMARY, ServerRole.read("f"));          // PostgreSQL
        assertEquals(ServerRole.STANDBY, ServerRole.read("t"));
        assertEquals(ServerRole.PRIMARY, ServerRole.read("0"));          // MySQL
        assertEquals(ServerRole.STANDBY, ServerRole.read("1"));
        assertEquals(ServerRole.PRIMARY, ServerRole.read("READ_WRITE")); // SQL Server
        assertEquals(ServerRole.STANDBY, ServerRole.read("READ_ONLY"));
        assertEquals(ServerRole.PRIMARY, ServerRole.read("PRIMARY"));    // Oracle
        assertEquals(ServerRole.STANDBY, ServerRole.read("PHYSICAL STANDBY"));
        assertEquals(ServerRole.UNKNOWN, ServerRole.read(null));
        assertEquals(ServerRole.UNKNOWN, ServerRole.read("something new"));
    }

    /** The one this class exists for: the right node out of three. */
    @Test
    void theListSkipsTheServersOfTheWrongKind() throws SQLException {
        List<String> opened = new ArrayList<>();
        List<String> givenBack = new ArrayList<>();
        HostList hosts = HostList.parse("a:1,b:2,c:3", 0).looking(TargetServer.PRIMARY);

        String chosen = hosts.open(host -> {
            opened.add(host.host());
            return host.host();
        }, roles(givenBack,
                "a", ServerRole.STANDBY, "b", ServerRole.STANDBY, "c", ServerRole.PRIMARY));

        assertEquals("c", chosen);
        assertEquals(List.of("a", "b", "c"), opened, "it stopped looking too early or too late");
        assertEquals(List.of("a", "b"), givenBack,
                "a connection to a server of the wrong kind was left open");
    }

    /** And it says what it found rather than blaming the network. */
    @Test
    void whenNoneFitsTheMessageNamesWhatEachOneSaid() {
        HostList hosts = HostList.parse("a:1,b:2", 0).looking(TargetServer.SECONDARY);
        SQLException none = assertThrows(SQLException.class,
                () -> hosts.open(host -> host.host(),
                        roles(new ArrayList<>(), "a", ServerRole.PRIMARY,
                                "b", ServerRole.PRIMARY)));
        assertTrue(none.getMessage().contains("is a primary"),
                "the message should say what was found: " + none.getMessage());
        assertEquals("08004", none.getSQLState(),
                "a server of the wrong kind is not the same failure as one that is down");
    }

    /** With no preference nothing is asked at all - one round trip saved. */
    @Test
    void withAnyTargetTheQuestionIsNotAsked() throws SQLException {
        List<String> asked = new ArrayList<>();
        HostList hosts = HostList.parse("a:1", 0);
        String chosen = hosts.open(host -> host.host(),
                new HostList.Roles<String>() {
                    @Override
                    public ServerRole of(String opened) {
                        asked.add(opened);
                        return ServerRole.PRIMARY;
                    }

                    @Override
                    public void giveBack(String opened) {
                    }
                });
        assertEquals("a", chosen);
        assertEquals(List.of(), asked, "a connection with no preference paid for a round trip");
    }

    private static HostList.Roles<String> roles(List<String> givenBack, Object... pairs) {
        return new HostList.Roles<>() {
            @Override
            public ServerRole of(String opened) {
                for (int i = 0; i < pairs.length; i += 2) {
                    if (pairs[i].equals(opened)) {
                        return (ServerRole) pairs[i + 1];
                    }
                }
                return ServerRole.UNKNOWN;
            }

            @Override
            public void giveBack(String opened) {
                givenBack.add(opened);
            }
        };
    }
}
