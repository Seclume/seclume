package space.seclume;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import space.seclume.jfr.Observed;
import space.seclume.jfr.SeclumeEvents;
import space.seclume.jfr.StatementListener;

/**
 * The same statement, two hundred times, in a tenth of a second.
 *
 * <p>Slow-query logging finds the statement that takes a second. It cannot
 * find the two hundred statements of a millisecond each that add up to the
 * same second, because every one of them is healthy on its own and nothing
 * that looks at statements one at a time can see the shape. That is the N+1,
 * and it is the most common performance defect in applications that use an
 * object mapper - not because anybody writes it deliberately, but because a
 * {@code for} loop over a collection and a lazy association look identical in
 * the source.
 *
 * <p><b>What is counted, and why that is the right thing to count.</b> Not
 * statements per second, which says nothing - a busy application runs
 * thousands and should. What says something is <b>the same shape, repeated,
 * on one thread, inside one moment</b>. One thread, because an N+1 is a loop
 * in somebody's method and a loop runs on the thread that entered it. One
 * shape, because a hundred different statements are a complicated request and
 * a hundred identical ones are a loop. And a moment, because the same
 * statement run a hundred times over an hour is a cache doing its job.
 *
 * <pre>
 * QueryStorms storms = QueryStorms.watching(storm -&gt;
 *         log.warn("{} ran {} times in {} ms", storm.fingerprint(),
 *                  storm.executions(), storm.within().toMillis()));
 * storms.install();
 * </pre>
 *
 * <p>It is also a {@code space.seclume.QueryStorm} Flight Recorder event, with
 * a stack trace - and the stack trace is the answer, because the fingerprint
 * says <i>what</i> is looping and only the stack says <i>where</i>.
 *
 * <h2>What it carries</h2>
 *
 * <p>The fingerprint and nothing else, which is not a limitation but the
 * reason this can be on by default. A detector that reported the statement
 * text would be a detector that writes literals into a log at the moment an
 * application is already under load - see {@link QueryFingerprint}.
 *
 * <h2>The one listener</h2>
 *
 * <p>{@link Observed#listen} takes one listener and that is deliberate: a list
 * would be a plugin system on the statement path, paid for by every
 * application. So this one composes explicitly -
 * {@link #alongside(StatementListener)} - and the application decides the
 * order rather than a framework.
 */
public final class QueryStorms implements StatementListener {

    /** What was found. */
    public record Storm(String kind, String fingerprint, int executions, Duration within) {
    }

    /** The same shape this often, inside the window, is a storm. */
    private static final int DEFAULT_THRESHOLD = 20;
    /** How long a window lasts before the counting starts again. */
    private static final Duration DEFAULT_WINDOW = Duration.ofSeconds(1);
    /**
     * How many distinct shapes a thread is tracked for at once.
     *
     * <p>Bounded because this is per thread and threads can be many. Eight is
     * comfortably more than a loop produces - an N+1 with three associations
     * is three shapes - and a request that genuinely runs nine different
     * statements is not what this is looking for.
     */
    private static final int SHAPES_PER_THREAD = 8;

    private final int threshold;
    private final Duration window;
    private final Consumer<Storm> report;
    private final StatementListener next;

    /**
     * What one thread has run lately.
     *
     * <p>A thread local and therefore uncontended, which matters because this
     * sits on the statement path of every statement in the process. It dies
     * with its thread, which is also what makes it safe on virtual threads:
     * the state is a few tens of bytes and it is not pooled anywhere.
     */
    private final ThreadLocal<Window> recent = ThreadLocal.withInitial(Window::new);

    private static final class Window {
        private long startedAt;
        private final Map<String, int[]> counts = new LinkedHashMap<>();
        private final java.util.Set<String> reported = new java.util.HashSet<>();
    }

    private QueryStorms(int threshold, Duration window, Consumer<Storm> report,
                        StatementListener next) {
        this.threshold = threshold;
        this.window = window;
        this.report = report;
        this.next = next;
    }

    /** With the defaults: twenty of a shape inside one second. */
    public static QueryStorms watching(Consumer<Storm> report) {
        return new QueryStorms(DEFAULT_THRESHOLD, DEFAULT_WINDOW, report, null);
    }

    /**
     * With a threshold and a window of your own.
     *
     * @param threshold how many executions of one shape make a storm
     * @param window    how long the counting runs before it starts again
     * @throws IllegalArgumentException for a threshold below two or a window
     *                                  that is not positive
     */
    public static QueryStorms watching(int threshold, Duration window, Consumer<Storm> report) {
        if (threshold < 2) {
            throw new IllegalArgumentException(
                    "a storm is a repetition, so the threshold starts at 2, not " + threshold);
        }
        if (window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("the window has to be positive, not " + window);
        }
        return new QueryStorms(threshold, window, report, null);
    }

    /** The same, also handing every statement on to another listener. */
    public QueryStorms alongside(StatementListener other) {
        return new QueryStorms(threshold, window, report, other);
    }

    /**
     * Installs this as <b>the</b> statement listener.
     *
     * <p>Replaces whatever was installed before. An application that also
     * traces composes the two with {@link #alongside} rather than calling
     * this twice.
     */
    public void install() {
        Observed.listen(this);
    }

    @Override
    public Span begin(String kind) {
        Span inner = next == null ? null : next.begin(kind);
        return (fingerprint, rows, failed) -> {
            count(kind, fingerprint);
            if (inner != null) {
                inner.end(fingerprint, rows, failed);
            }
        };
    }

    private void count(String kind, String fingerprint) {
        if (fingerprint == null) {
            return;
        }
        Window seen = recent.get();
        long now = System.nanoTime();
        if (seen.startedAt == 0 || now - seen.startedAt > window.toNanos()) {
            // A new window. Everything before it is somebody else's request.
            seen.startedAt = now;
            seen.counts.clear();
            seen.reported.clear();
        }
        int[] count = seen.counts.get(fingerprint);
        if (count == null) {
            if (seen.counts.size() >= SHAPES_PER_THREAD) {
                // More shapes than a loop produces: this is a complicated
                // request, not a storm. The oldest goes, which is the one
                // least likely to be the one repeating.
                String oldest = seen.counts.keySet().iterator().next();
                seen.counts.remove(oldest);
            }
            count = new int[1];
            seen.counts.put(fingerprint, count);
        }
        count[0]++;
        if (count[0] < threshold || !seen.reported.add(fingerprint)) {
            // Under the threshold, or already reported inside this window.
            // Reported once per window and not once per statement: a loop of
            // a thousand would otherwise produce nine hundred and eighty
            // reports of itself.
            return;
        }
        announce(kind, fingerprint, count[0], Duration.ofNanos(now - seen.startedAt));
    }

    private void announce(String kind, String fingerprint, int executions, Duration within) {
        SeclumeEvents.QueryStorm event = new SeclumeEvents.QueryStorm();
        if (event.isEnabled()) {
            event.kind = kind;
            event.fingerprint = fingerprint;
            event.executions = executions;
            event.windowMillis = within.toMillis();
            event.commit();
        }
        if (report != null) {
            try {
                report.accept(new Storm(kind, fingerprint, executions, within));
            } catch (RuntimeException theirs) {
                // A reporter that throws must not take the statement with it.
                // The application asked to be told about a performance
                // problem; failing its query over it would be a worse one.
            }
        }
    }
}
