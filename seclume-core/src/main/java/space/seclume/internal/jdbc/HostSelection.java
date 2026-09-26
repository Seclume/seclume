package space.seclume.internal.jdbc;

import java.util.Locale;

/**
 * How a list of servers picks the one to open the next connection to.
 *
 * <p>Written as {@code hostSelection} in the URL.
 */
public enum HostSelection {

    /**
     * The list as written, starting with the server that worked last - the
     * default, and exactly what a list did before there was a choice.
     */
    ORDERED,

    /**
     * Best measured first: servers that just failed last, then by connect
     * time weighted by failure rate, with a stale measurement renewed - see
     * {@link HostQuality}.
     */
    QUALITY;

    /**
     * Reads the URL value, and refuses a spelling it does not know - for the
     * reason {@link TargetServer#of} gives.
     */
    public static HostSelection of(String text) {
        if (text == null || text.isBlank()) {
            return ORDERED;
        }
        return switch (text.trim().toLowerCase(Locale.ROOT)) {
            case "ordered", "priority", "failover" -> ORDERED;
            case "quality", "fastest", "best" -> QUALITY;
            default -> throw new IllegalArgumentException(
                    "hostSelection=" + text + " is not one of ordered, quality");
        };
    }

    @Override
    public String toString() {
        return name().toLowerCase(Locale.ROOT);
    }
}
