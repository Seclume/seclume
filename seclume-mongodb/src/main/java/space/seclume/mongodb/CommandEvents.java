package space.seclume.mongodb;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.mongodb.event.CommandFailedEvent;
import com.mongodb.event.CommandListener;
import com.mongodb.event.CommandStartedEvent;
import com.mongodb.event.CommandSucceededEvent;

import space.seclume.jfr.Observed;
import space.seclume.mongodb.internal.CommandShape;

/**
 * The official driver's commands as seclume's {@code Query} events - by
 * their shape ({@link CommandShape}), never their values, as seclume's own
 * driver records them. Nothing is kept when nobody records and nobody
 * listens: {@link Observed#beginQuery} hands back null then.
 */
final class CommandEvents implements CommandListener {

    /** What a started command needs at its end. */
    private record Started(Observed.Statement statement, String shape) {
    }

    /** By request id, which the driver numbers across the whole process. */
    private final Map<Integer, Started> running = new ConcurrentHashMap<>();

    @Override
    public void commandStarted(CommandStartedEvent event) {
        if (!CommandShape.recorded(event.getCommand())) {
            return;
        }
        Observed.Statement statement = Observed.beginQuery("mongodb");
        if (statement != null) {
            running.put(event.getRequestId(), new Started(statement,
                    CommandShape.shape(event.getDatabaseName(), event.getCommand())));
        }
    }

    @Override
    public void commandSucceeded(CommandSucceededEvent event) {
        Started started = running.remove(event.getRequestId());
        if (started != null) {
            Observed.endQuery(started.statement(), "mongodb", started.shape(),
                    space.seclume.QueryFingerprint.Dialect.GENERIC,
                    CommandShape.rows(event.getResponse()), false);
        }
    }

    @Override
    public void commandFailed(CommandFailedEvent event) {
        Started started = running.remove(event.getRequestId());
        if (started != null) {
            Observed.endQuery(started.statement(), "mongodb", started.shape(),
                    space.seclume.QueryFingerprint.Dialect.GENERIC, 0, true);
        }
    }
}
