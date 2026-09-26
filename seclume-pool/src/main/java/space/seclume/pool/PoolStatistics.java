package space.seclume.pool;

/**
 * The state of a pool, in numbers.
 *
 * <p>Meant for metrics and for troubleshooting. These are exclusively numbers
 * and the pool name - no user, no host name, nothing about the secret source.
 * That is deliberate: these values end up in dashboards, log lines and support
 * attachments.
 *
 * @param name           the name of the pool
 * @param total          how many connections there are in total
 * @param active         how many of them are borrowed
 * @param idle           how many sit free in the pool
 * @param waiting        how many threads are waiting right now
 * @param borrowed       how often a connection has been handed out in total
 * @param created        how many connections have been opened
 * @param retired        how many have been closed
 * @param timeouts       how often nobody got one in time
 * @param prewarmed      how many replacements were opened before the
 *                       connection they replace was retired - see
 *                       {@code SeclumePool.prewarm}
 * @param leaksReported  how often a forgotten connection has been reported
 * @param renewed        how often a connection that broke while it was borrowed
 *                       was rebuilt underneath the application
 */
public record PoolStatistics(String name, int total, int active, int idle, int waiting,
                             long borrowed, long created, long retired, long timeouts,
                             long leaksReported, long renewed, long prewarmed) {

    /** The 0.9.0 form, without {@code prewarmed}: kept so that code built against it still links. */
    public PoolStatistics(String name, int total, int active, int idle, int waiting,
                          long borrowed, long created, long retired, long timeouts,
                          long leaksReported, long renewed) {
        this(name, total, active, idle, waiting, borrowed, created, retired, timeouts,
                leaksReported, renewed, 0);
    }

    @Override
    public String toString() {
        return "SeclumePool[" + name + ": total=" + total + ", active=" + active
                + ", idle=" + idle + ", waiting=" + waiting + ", borrowed=" + borrowed
                + ", created=" + created + ", retired=" + retired + ", timeouts=" + timeouts
                + ", leaks=" + leaksReported + ", renewed=" + renewed
                + ", prewarmed=" + prewarmed + "]";
    }
}
