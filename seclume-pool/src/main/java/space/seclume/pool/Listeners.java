package space.seclume.pool;

import java.util.List;

/** Several {@link PoolListener}s as one - an array walked in order, nothing else on the hot path. */
final class Listeners implements PoolListener {

    private final PoolListener[] all;

    private Listeners(PoolListener[] all) {
        this.all = all;
    }

    /** {@code null} for none, the listener itself for one, a fan-out for more. */
    static PoolListener of(List<PoolListener> listeners) {
        PoolListener[] all = listeners.toArray(new PoolListener[0]);
        return all.length == 0 ? null : all.length == 1 ? all[0] : new Listeners(all);
    }

    @Override
    public void acquired(long waitedNanos) {
        for (PoolListener listener : all) {
            listener.acquired(waitedNanos);
        }
    }

    @Override
    public void released(long heldNanos) {
        for (PoolListener listener : all) {
            listener.released(heldNanos);
        }
    }

    @Override
    public void opened(long tookNanos) {
        for (PoolListener listener : all) {
            listener.opened(tookNanos);
        }
    }

    @Override
    public void resetRefused() {
        for (PoolListener listener : all) {
            listener.resetRefused();
        }
    }
}
