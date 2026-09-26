package space.seclume.postgresql;

/**
 * One {@code NOTIFY} the server delivered to this connection.
 *
 * @param processId the backend that sent it - the same as this connection's
 *                  when it notified itself
 * @param channel   the channel it was sent on
 * @param payload   what came with it, empty when nothing did
 */
public record PgNotification(int processId, String channel, String payload) {
}
