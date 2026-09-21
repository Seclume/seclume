package space.seclume.pool;

import jdk.jfr.Category;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

/**
 * What the pool tells the Flight Recorder.
 *
 * <p>Declared here rather than beside the driver events, and that is the
 * interesting part. This module's comment says it knows {@code DataSource}
 * and nothing else - it pools other people's drivers exactly as it pools
 * these - and reaching into {@code seclume.core} for an event class would
 * quietly overturn that for the sake of tidiness. {@code jdk.jfr} is a JDK
 * module, so an event of its own costs the pool no dependency at all.
 *
 * <p>The same rule applies as everywhere else: nothing here is derived from a
 * credential or from a statement. The pool never sees either, which makes
 * that easy to keep.
 */
final class PoolEvents {

    private PoolEvents() {
    }

    /**
     * Time spent waiting for a connection to become free.
     *
     * <p>The number an operator actually wants when the application is slow
     * and the database is idle - and the one that is otherwise invisible,
     * because from the outside a pool wait and a slow query look the same.
     *
     * <p>No threshold: the event is only raised when there was a wait at all,
     * and then any length of it is information. A recording that wants to
     * ignore short ones can filter; a recording that never saw them cannot.
     */
    @Name("space.seclume.PoolWait")
    @Label("Pool Wait")
    @Category({"seclume", "Pool"})
    @Description("Waiting for a pooled connection to become free")
    @StackTrace(false)
    static final class Wait extends Event {

        /** Public and explicit because the Flight Recorder instantiates it. */
        Wait() {
        }

        @Label("Pool")
        public String pool;

        @Label("In Use")
        @Description("Connections already borrowed when the wait began")
        public long inUse;

        @Label("Timed Out")
        @Description("Whether the wait ended in a timeout rather than a connection")
        public boolean timedOut;
    }

    /** A handle, or {@code null} when nobody is recording. */
    static Wait beginWait() {
        Wait event = new Wait();
        if (!event.isEnabled()) {
            return null;
        }
        event.begin();
        return event;
    }

    static void endWait(Wait event, String pool, long inUse, boolean timedOut) {
        if (event == null) {
            return;
        }
        event.end();
        if (!event.shouldCommit()) {
            return;
        }
        event.pool = pool;
        event.inUse = inUse;
        event.timedOut = timedOut;
        event.commit();
    }
}
