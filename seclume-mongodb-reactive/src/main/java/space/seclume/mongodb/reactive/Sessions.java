package space.seclume.mongodb.reactive;

/** The sync session behind a reactive one; a session of another driver is refused. */
final class Sessions {

    private Sessions() {
    }

    static com.mongodb.client.ClientSession sync(
            com.mongodb.reactivestreams.client.ClientSession session) {
        if (session == null) {
            return null;
        }
        if (!(session instanceof ReactiveClientSession ours)) {
            throw new IllegalArgumentException("the session was started by another client");
        }
        return ours.sync;
    }
}
