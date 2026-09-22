package space.seclume.internal.jdbc;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Several servers for one database, and the order to try them in.
 *
 * <p>This is failover at the moment of connecting - the case that covers a
 * rolling update, a restarted node, a switched-over cluster. It is deliberately
 * the whole of it: a connection that is already open cannot be moved, and
 * pretending otherwise is how a driver quietly runs a statement twice.
 *
 * <p><b>Which failure moves on to the next server.</b> Only a connection one -
 * SQLState class {@code 08}. A rejected password or a missing database is not a
 * reason to ask the next server the same question: the answer would be the
 * same, and on the way there the account collects failed logins on every node
 * in the list. Those errors are passed straight through.
 *
 * <p>The last server that worked is tried first next time. Without that, a
 * list whose first entry is down pays for the timeout on every single connect,
 * which turns a failover into a permanent slowdown.
 */
public final class HostList {

    /** One server: where it listens. */
    public record Host(String host, int port) {

        @Override
        public String toString() {
            return host + ":" + port;
        }
    }

    /** What opens a connection to one server. */
    @FunctionalInterface
    public interface Opener<T> {
        T open(Host host) throws SQLException;
    }

    private final List<Host> hosts;
    /**
     * Which kind of server this list is looking for.
     *
     * <p>It lives here rather than in each driver's settings for a plain
     * reason: it is a property of the list, not of the connection, and the
     * four settings records would otherwise each grow a component and eight
     * constructors would each grow an argument. A list of one with no
     * preference behaves exactly as it always did.
     */
    private final TargetServer target;
    /** The one that worked last - tried first, so a dead head costs nothing. */
    private volatile int preferred;

    private HostList(List<Host> hosts, TargetServer target) {
        this.hosts = List.copyOf(hosts);
        this.target = target;
    }

    /** The same servers, looking for a particular kind of one. */
    public HostList looking(TargetServer wanted) {
        return wanted == target ? this : new HostList(hosts, wanted);
    }

    /** What this list is looking for - {@link TargetServer#ANY} unless told. */
    public TargetServer target() {
        return target;
    }

    /** A single server, the ordinary case. */
    public static HostList of(String host, int port) {
        return new HostList(List.of(new Host(host, port)), TargetServer.ANY);
    }

    /**
     * Reads {@code db1:5432,db2:5432,db3} - the port may be left out and is
     * then the default one. Blanks around the commas are allowed because
     * people put them there.
     *
     * @throws IllegalArgumentException if the text names no server at all, or
     *         a port that is not a port - a typo here is better found at
     *         startup than at three in the morning
     */
    public static HostList parse(String text, int defaultPort) {
        List<Host> found = new ArrayList<>();
        for (String part : text.split(",")) {
            String entry = part.strip();
            if (entry.isEmpty()) {
                continue;
            }
            int colon = entry.lastIndexOf(':');
            // IPv6 in brackets: the colon inside is not a port separator.
            int bracket = entry.lastIndexOf(']');
            if (colon > bracket) {
                String host = entry.substring(0, colon).strip();
                String port = entry.substring(colon + 1).strip();
                found.add(new Host(host, parsePort(port, entry)));
            } else {
                found.add(new Host(entry, defaultPort));
            }
        }
        if (found.isEmpty()) {
            throw new IllegalArgumentException("no server in the host list: \"" + text + "\"");
        }
        return new HostList(found, TargetServer.ANY);
    }

    private static int parsePort(String text, String entry) {
        int port;
        try {
            port = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("\"" + entry + "\" has no usable port", e);
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("\"" + entry + "\" has no usable port");
        }
        return port;
    }

    /** The servers, in the order they were configured. */
    public List<Host> hosts() {
        return hosts;
    }

    /** The first server - what a driver reports as "the" host. */
    public Host first() {
        return hosts.get(0);
    }

    public int size() {
        return hosts.size();
    }

    /** The list as it is written in a URL - {@code parse} reads this back. */
    public String text() {
        StringBuilder text = new StringBuilder(); // seclume-allow: server names, not a secret
        for (Host host : hosts) {
            if (text.length() > 0) {
                text.append(',');
            }
            text.append(host.host()).append(':').append(host.port());
        }
        return text.toString();
    }

    /**
     * What a freshly opened connection says about the server behind it, and
     * how to give it back when it is the wrong one.
     *
     * <p>Two methods rather than one because a rejected connection has to be
     * closed, and only the caller knows how. A host list that left them open
     * would leak one per attempt, which on a three-node cluster asked for a
     * primary is two leaked sessions every time the primary moves.
     */
    public interface Roles<T> {

        /** Asks the server, or answers {@link ServerRole#UNKNOWN}. */
        ServerRole of(T opened) throws SQLException;

        /** Gives back a connection to a server that was the wrong kind. */
        void giveBack(T opened);
    }

    /**
     * The same, but only accepting a server of the kind asked for.
     *
     * <p>This is the difference between failing over and knowing where to.
     * Without it a list of three opens a connection to whichever node answers
     * first - and after a switchover that is a standby, so the application
     * connects successfully and fails on its first write, at exactly the
     * moment a cluster is least able to explain itself.
     *
     * <p>A server of the wrong kind is treated like one that did not answer:
     * closed, recorded, and the next one tried. <b>It is not an error on its
     * own</b> - a standby in a list asked for a primary is a normal state of
     * affairs during a switchover, not a misconfiguration.
     *
     * <p>When none of them fits, the message says what each one said. "None of
     * the 3 servers could be reached" would be wrong and, worse, would send
     * whoever reads it to look at the network.
     */
    public <T> T open(Opener<T> opener, Roles<T> roles) throws SQLException {
        TargetServer wanted = target;
        if (!wanted.needsToAsk()) {
            return open(opener);
        }
        int start = preferred;
        SQLException failure = null;
        List<String> refused = new ArrayList<>();
        for (int i = 0; i < hosts.size(); i++) {
            int index = (start + i) % hosts.size();
            Host host = hosts.get(index);
            T opened = null;
            try {
                opened = opener.open(host);
                ServerRole role = roles.of(opened);
                if (wanted.accepts(role)) {
                    preferred = index;
                    return opened;
                }
                refused.add(host + " is a " + role.name().toLowerCase(java.util.Locale.ROOT));
                roles.giveBack(opened);
                opened = null;
                // Recorded like a failover, because that is what it is: this
                // connection is going somewhere else, and which node was
                // passed over is the fact somebody will want afterwards.
                Host next = hosts.get((index + 1) % hosts.size());
                space.seclume.jfr.Observed.failover(host.toString(), next.toString(),
                        "not the " + wanted + " this connection asked for");
            } catch (SQLException e) {
                if (opened != null) {
                    roles.giveBack(opened);
                }
                if (!isUnreachable(e)) {
                    throw e;
                }
                if (failure != null) {
                    e.addSuppressed(failure);
                }
                failure = e;
                Host next = hosts.get((index + 1) % hosts.size());
                space.seclume.jfr.Observed.failover(host.toString(), next.toString(),
                        e.getMessage());
            }
        }
        if (refused.isEmpty()) {
            throw new SQLException("none of the " + hosts.size() + " servers could be reached ("
                    + hosts + "): " + failure.getMessage(), "08001", failure);
        }
        String reached = String.join(", ", refused);
        throw new SQLException("no server in " + hosts + " is a " + wanted
                + " - " + reached + (failure == null ? ""
                        : ", and the rest could not be reached: " + failure.getMessage()),
                "08004", failure);
    }

    /**
     * Opens a connection, taking the next server when one cannot be reached.
     *
     * <p>What comes back is the first connection that worked. If none did, the
     * failure of the last server is thrown with the others attached as
     * suppressed exceptions - all of them, because "the database is not
     * reachable" without saying what each server answered is a message that
     * helps nobody.
     */
    public <T> T open(Opener<T> opener) throws SQLException {
        if (hosts.size() == 1) {
            return opener.open(hosts.get(0));       // nothing to fail over to
        }
        int start = preferred;
        SQLException failure = null;
        for (int i = 0; i < hosts.size(); i++) {
            int index = (start + i) % hosts.size();
            Host host = hosts.get(index);
            try {
                T opened = opener.open(host);
                preferred = index;                  // this one answers, ask it first
                return opened;
            } catch (SQLException e) {
                if (!isUnreachable(e)) {
                    throw e;                        // not the server's fault
                }
                if (failure != null) {
                    e.addSuppressed(failure);
                }
                failure = e;
                // Recorded here rather than where the connection finally
                // succeeds, because the interesting fact is which server did
                // not answer - and on a run where none of them does, that is
                // the only place it is known.
                Host next = hosts.get((index + 1) % hosts.size());
                space.seclume.jfr.Observed.failover(host.toString(), next.toString(),
                        e.getMessage());
            }
        }
        throw new SQLException("none of the " + hosts.size() + " servers could be reached ("
                + hosts + "): " + failure.getMessage(), "08001", failure);
    }

    /** SQLState class 08 - the connection, as opposed to what was asked. */
    private static boolean isUnreachable(SQLException failure) {
        String state = failure.getSQLState();
        return state != null && state.startsWith("08");
    }

    @Override
    public String toString() {
        return hosts.toString();
    }
}
