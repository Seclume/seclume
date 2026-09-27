package space.seclume.tck;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

/**
 * The Flight Recorder events a piece of code emits - for tests that prove an
 * extension records what it does, and nothing it should not.
 *
 * <pre>
 * List&lt;RecordedEvent&gt; events = Recorded.during(() -&gt; client.call(), "space.seclume.SecretUse");
 * </pre>
 */
public final class Recorded {

    /** The code under test. */
    public interface Action {
        void run() throws Exception;
    }

    private Recorded() {
    }

    /** Runs {@code action} with the named events on, and returns what it emitted of them. */
    public static List<RecordedEvent> during(Action action, String... names) throws Exception {
        Path file = Files.createTempFile("seclume-recorded-", ".jfr");
        try (Recording recording = new Recording()) {
            for (String name : names) {
                recording.enable(name).withoutThreshold();
            }
            recording.start();
            action.run();
            recording.stop();
            recording.dump(file);
            Set<String> wanted = Set.of(names);
            return RecordingFile.readAllEvents(file).stream()
                    .filter(event -> wanted.contains(event.getEventType().getName()))
                    .toList();
        } finally {
            try {
                Files.deleteIfExists(file);
            } catch (IOException e) {
                // a temporary file
            }
        }
    }
}
