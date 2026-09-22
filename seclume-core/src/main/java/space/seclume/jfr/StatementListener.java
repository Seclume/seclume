package space.seclume.jfr;

/**
 * Somebody who wants to be told about every statement, while it runs.
 *
 * <p>There is exactly one reason this exists beside the Flight Recorder
 * events, and it is not that a second recording is wanted. <b>A trace span
 * cannot be produced from a recording.</b> A span belongs to the request that
 * caused it, and which request that is lives in the calling thread's context
 * at the moment the statement runs; by the time a
 * {@code jdk.jfr.consumer.RecordingStream} sees the event the thread has long
 * moved on, and the span would be an orphan with the right duration and no
 * parent. That is why the metrics bridge could be built with no hook at all
 * (see {@code SeclumeQueryMetrics}) and tracing cannot.
 *
 * <p>So this is one interface, no dependency, and a no-op until somebody
 * registers one - {@link Observed#listen}. Nothing here is a plugin system:
 * there is one listener, the application installs it, and the drivers do not
 * know it exists.
 *
 * <p><b>It is given the fingerprint and never the statement.</b> The same rule
 * as everywhere else in this package, and enforced the same way: the text does
 * not leave {@link Observed}, so a listener written later cannot reach for it.
 * A span attribute carrying a bind value would be worse than one in a
 * recording, because a trace leaves the building.
 */
public interface StatementListener {

    /**
     * A statement is starting on this thread.
     *
     * <p>Called on the application's own thread inside the JDBC call, which is
     * the whole point: whatever ambient context a tracer keeps is the right
     * one here and nowhere else.
     *
     * @param kind the database, such as {@code postgresql}
     * @return something to hand back to {@link Span#end}, never {@code null}
     */
    Span begin(String kind);

    /** One statement in flight. */
    interface Span {

        /**
         * The statement has finished.
         *
         * @param fingerprint the statement with every value taken out - see
         *                    {@link space.seclume.QueryFingerprint}
         * @param rows        rows read or rows changed, whichever the
         *                    statement produced
         * @param failed      whether it threw
         */
        void end(String fingerprint, long rows, boolean failed);
    }
}
