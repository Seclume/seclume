package space.seclume.internal;

import java.util.ArrayList;
import java.util.List;

import space.seclume.Flight;

/**
 * The ring the four channels write into - see {@link Flight} for why.
 *
 * <p>One per connection, written only by the thread that owns that connection,
 * which is what lets it be an array and an index rather than a queue. A
 * cancellation reaches the connection from another thread, but it writes
 * nothing here: what it sends is eight or sixteen bytes that the reading
 * thread never accounts for, and a recorder that tried to be thread-safe for
 * that one case would pay for it on every message of every connection.
 *
 * <p><b>Types and counts, never bytes.</b> The single rule of this class, and
 * the reason it can exist at all in a library about what does not end up in
 * memory.
 */
public final class FlightRecorder {

    /** What {@code seclume.flight} sets when it is given no number. */
    public static final int DEFAULT_SIZE = 32;
    /** More than this is a log, not a flight recorder. */
    private static final int MOST = 4096;

    private final String[] types;
    private final int[] lengths;
    private final boolean[] outgoing;
    private int at;
    private boolean wrapped;
    private long count;

    private FlightRecorder(int size) {
        this.types = new String[size]; // seclume-allow: message type names, never a payload
        this.lengths = new int[size];
        this.outgoing = new boolean[size];
    }

    /**
     * A recorder of this many messages, or {@code null} for none.
     *
     * <p>Null and not an empty recorder: the channels check for null once per
     * message and an object that does nothing would still cost the call. The
     * common case is that nobody asked for this.
     */
    public static FlightRecorder of(int size) {
        if (size <= 0) {
            return null;
        }
        return new FlightRecorder(Math.min(size, MOST));
    }

    /**
     * What the URL option or the system property asked for.
     *
     * @param option the {@code flightRecorder} option, or null
     * @return a recorder, or {@code null} when nobody asked
     */
    public static FlightRecorder from(String option) {
        String asked = option != null ? option
                : System.getProperty("seclume.flight"); // seclume-allow: a diagnostic size, not a secret
        if (asked == null || asked.isBlank()) {
            return null;
        }
        String trimmed = asked.trim();
        if ("true".equalsIgnoreCase(trimmed) || "on".equalsIgnoreCase(trimmed)) {
            return of(DEFAULT_SIZE);
        }
        if ("false".equalsIgnoreCase(trimmed) || "off".equalsIgnoreCase(trimmed)) {
            return null;
        }
        try {
            return of(Integer.parseInt(trimmed));
        } catch (NumberFormatException notANumber) {
            // A diagnostic must not be the reason a connection fails to open.
            return of(DEFAULT_SIZE);
        }
    }

    /** Records one message. The type is a constant, not something read off the wire. */
    public void record(boolean sent, String type, int bytes) {
        types[at] = type;
        lengths[at] = bytes;
        outgoing[at] = sent;
        at++;
        count++;
        if (at == types.length) {
            at = 0;
            wrapped = true;
        }
    }

    /** What is in the ring, oldest first. */
    public List<Flight.Message> recent() {
        int size = wrapped ? types.length : at;
        List<Flight.Message> out = new ArrayList<>(size);
        int start = wrapped ? at : 0;
        for (int i = 0; i < size; i++) {
            int index = (start + i) % types.length;
            out.add(new Flight.Message(outgoing[index], types[index], lengths[index]));
        }
        return out;
    }

    public long messages() {
        return count;
    }

    /**
     * The tail of the recording, for an exception message.
     *
     * <p>Attached where a broken connection is reported, because that is the
     * one place somebody is certain to look and the recording is worthless if
     * it has to be fetched separately after the fact.
     */
    public String tail(int howMany) {
        List<Flight.Message> all = recent();
        StringBuilder out = new StringBuilder("the last ");
        int from = Math.max(0, all.size() - howMany);
        out.append(all.size() - from).append(" messages were:");
        for (int i = from; i < all.size(); i++) {
            out.append("\n  ").append(all.get(i));
        }
        return out.toString();
    }
}
