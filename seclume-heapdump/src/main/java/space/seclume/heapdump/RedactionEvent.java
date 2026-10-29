package space.seclume.heapdump;

import jdk.jfr.Category;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

/**
 * A heap dump redacted, or one that could not be made clean - in the Flight
 * Recorder beside seclume's other events, though this module depends on none
 * of them. The dump is named by its file; counts only, never a value.
 */
@Name("space.seclume.HeapDumpRedaction")
@Label("Heap Dump Redaction")
@Category({"seclume", "Diagnostics"})
@Description("A heap dump redacted into a copy, or one that could not be made clean")
@StackTrace(false)
public final class RedactionEvent extends Event {

    /** Public and explicit because the Flight Recorder instantiates it. */
    public RedactionEvent() {
    }

    @Label("Dump")
    @Description("The file redacted")
    public String dump;

    @Label("Succeeded")
    @Description("Whether a clean copy was written")
    public boolean succeeded;

    @Label("Places")
    @Description("Byte ranges overwritten")
    public long places;

    @Label("Echoes")
    @Description("Of those, copies or parts of a discovered credential found elsewhere")
    public long echoes;

    @Label("String Hashes")
    @Description("String hash fields cleared")
    public long stringHashes;

    @Label("Reason")
    @Description("Why no clean copy was written; empty when one was")
    public String reason;
}
