package space.seclume.internal.jdbc;

import java.util.Locale;

/**
 * Which server of a list a connection is asking for.
 *
 * <p>The difference between a host list that merely reconnects and one that
 * knows where it is going. With several servers in the URL, a driver that
 * takes the first one that answers will happily open a connection to a
 * standby and then fail on the first write - and it will do it at the worst
 * moment, because that is when a switchover happens.
 *
 * <p>Written as {@code targetServerType} in the URL, which is the name
 * pgjdbc uses. Somebody migrating should not have to learn a second word for
 * the same idea.
 */
public enum TargetServer {

    /** Whatever answers first - the default, and what a single server means. */
    ANY,

    /** Only a server that accepts writes. */
    PRIMARY,

    /** Only a copy - for reports and other work that should stay off the primary. */
    SECONDARY;

    /**
     * Whether a server that says this is acceptable.
     *
     * <p><b>{@link ServerRole#UNKNOWN} is accepted by every target</b>, and
     * that is the one judgement call in this class. A server that cannot
     * describe itself - an old version, an account without the right - would
     * otherwise be excluded from a list it belongs to, and the failure would
     * arrive as "none of the servers could be reached" on a cluster where
     * every one of them is up. Refusing to connect over an unanswered
     * question is worse than connecting to a server that turns out to be the
     * wrong kind, because the second failure says what it is.
     */
    public boolean accepts(ServerRole role) {
        return switch (this) {
            case ANY -> true;
            case PRIMARY -> role != ServerRole.STANDBY;
            case SECONDARY -> role != ServerRole.PRIMARY;
        };
    }

    /** Whether asking at all is worth a round trip. */
    public boolean needsToAsk() {
        return this != ANY;
    }

    /**
     * Reads the URL value, and refuses a spelling it does not know.
     *
     * <p>Refuses rather than defaulting to {@link #ANY}: a typo in
     * {@code targetServerType=primry} that quietly meant "any server" would
     * send writes to a standby, and the URL would look correct while doing it.
     */
    public static TargetServer of(String text) {
        if (text == null || text.isBlank()) {
            return ANY;
        }
        return switch (text.trim().toLowerCase(Locale.ROOT)) {
            case "any" -> ANY;
            case "primary", "master" -> PRIMARY;
            case "secondary", "replica", "standby", "slave" -> SECONDARY;
            default -> throw new IllegalArgumentException(
                    "targetServerType=" + text + " is not one of any, primary, secondary");
        };
    }

    @Override
    public String toString() {
        return name().toLowerCase(Locale.ROOT);
    }
}
