package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

/**
 * What a failover costs, as opposed to how often one happened.
 *
 * <p>The event used to be a count, and a count cannot answer the question an
 * operator actually has after a switchover: <b>where did the twenty seconds
 * go?</b> A server that refuses a connection costs a millisecond. A server
 * whose packets are dropped silently costs the whole connect timeout, spent
 * inside {@code getConnection} with nothing to show for it. Those two are the
 * same number in a count and nothing alike in practice.
 *
 * <p>No server here and none wanted: the openers below fail on purpose and
 * take a known time doing it, which is the only way to assert that the
 * duration is the attempt's rather than zero or the whole loop's.
 */
@Timeout(60)
class FailoverEventTest {

    /** Long enough that a duration of zero cannot be mistaken for it. */
    private static final long SLOW_MILLIS = 60;

    @Test
    void eachPassedOverServerIsRecordedWithHowLongItTook(@TempDir Path directory)
            throws Exception {
        HostList hosts = HostList.parse("dead-one:5432,dead-two:5432,live:5432", 5432);
        Path file = directory.resolve("failover.jfr");

        try (Recording recording = new Recording()) {
            // Threshold zero: the two failures below are tens of milliseconds
            // and JFR's default would record neither.
            recording.enable("space.seclume.Failover").withThreshold(Duration.ZERO);
            recording.start();

            String opened = hosts.open(host -> {
                if (host.host().startsWith("dead")) {
                    sleep(SLOW_MILLIS);
                    throw new SQLException("nothing on " + host, "08001");
                }
                return host.toString();
            });
            assertEquals("live:5432", opened);

            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(file).stream()
                .filter(event -> event.getEventType().getName().equals("space.seclume.Failover"))
                .toList();

        assertEquals(2, events.size(),
                "two servers were passed over and the third worked, so there are two "
                        + "events - the one that worked is not a failover: " + events);

        RecordedEvent first = events.get(0);
        assertEquals("dead-one:5432", first.getString("from"));
        assertEquals("dead-two:5432", first.getString("to"));
        assertEquals(1, first.getInt("attempt"));
        assertTrue(first.getString("reason").contains("nothing on"), first.getString("reason"));

        assertEquals("dead-two:5432", events.get(1).getString("from"));
        assertEquals("live:5432", events.get(1).getString("to"));
        assertEquals(2, events.get(1).getInt("attempt"));

        // The whole point: the duration is that server's, and it is real.
        for (RecordedEvent event : events) {
            assertTrue(event.getDuration().toMillis() >= SLOW_MILLIS / 2,
                    "a server that took " + SLOW_MILLIS + " ms to fail was recorded as "
                            + event.getDuration() + " - then the event is not timing the "
                            + "attempt");
            assertTrue(event.getDuration().toMillis() < SLOW_MILLIS * 10,
                    "the event covers " + event.getDuration() + " for one attempt of "
                            + SLOW_MILLIS + " ms - then it is timing the whole loop");
        }
    }

    /**
     * A list where every server is dead still records every one of them.
     *
     * <p>This is the run where the recording is the only evidence there is:
     * nothing connected, so there is no connection to ask afterwards. An event
     * raised only on the way to a working server would be missing exactly when
     * it is most wanted.
     */
    @Test
    void aListWhereNothingAnswersRecordsAllOfIt(@TempDir Path directory) throws Exception {
        HostList hosts = HostList.parse("a:1,b:1,c:1", 5432);
        Path file = directory.resolve("all-dead.jfr");

        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.Failover").withThreshold(Duration.ZERO);
            recording.start();

            assertThrows(SQLException.class, () -> hosts.open(host -> {
                throw new SQLException("nothing on " + host, "08001");
            }));

            recording.stop();
            recording.dump(file);
        }

        List<RecordedEvent> events = RecordingFile.readAllEvents(file).stream()
                .filter(event -> event.getEventType().getName().equals("space.seclume.Failover"))
                .toList();
        assertEquals(3, events.size(), "three servers, three of them dead: " + events);
        assertEquals(List.of(1, 2, 3), events.stream().map(e -> e.getInt("attempt")).toList());
        // The last one points back at the first: the list is a ring, and a
        // reader of the recording should see that rather than a null. And it
        // is a:1 rather than a:5432 - the port is in the text, so the default
        // is not used. The first version of this assertion said 5432 and was
        // wrong about its own fixture rather than about the code.
        assertEquals("a:1", events.get(2).getString("to"));
    }

    /** One server that answers is not a failover, whatever else happens. */
    @Test
    void aConnectionThatWorksRaisesNothing(@TempDir Path directory) throws Exception {
        HostList hosts = HostList.parse("live-one:5432,live-two:5432", 5432);
        Path file = directory.resolve("quiet.jfr");

        try (Recording recording = new Recording()) {
            recording.enable("space.seclume.Failover").withThreshold(Duration.ZERO);
            recording.start();
            assertEquals("live-one:5432", hosts.open(host -> host.toString()));
            recording.stop();
            recording.dump(file);
        }

        assertTrue(RecordingFile.readAllEvents(file).stream()
                        .noneMatch(event -> event.getEventType().getName()
                                .equals("space.seclume.Failover")),
                "a connection that worked on the first server recorded a failover");
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }
}
