package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/** The registry of cached secrets wiped before a checkpoint. */
class CheckpointTest {

    private static final class Cache {
        final AtomicInteger wiped = new AtomicInteger();
        boolean fail;

        void wipe() {
            if (fail) {
                throw new IllegalStateException("cannot wipe");
            }
            wiped.incrementAndGet();
        }
    }

    @Test
    void everyRegisteredCacheIsWiped() {
        Cache one = new Cache();
        Cache two = new Cache();
        Checkpoint.register(one, Cache::wipe);
        Checkpoint.register(two, Cache::wipe);

        assertTrue(Checkpoint.wipeAll() >= 2);

        assertEquals(1, one.wiped.get());
        assertEquals(1, two.wiped.get());
    }

    @Test
    void oneCacheThatFailsDoesNotSpareTheOthers() {
        Cache failing = new Cache();
        failing.fail = true;
        Cache fine = new Cache();
        Checkpoint.register(failing, Cache::wipe);
        Checkpoint.register(fine, Cache::wipe);

        IllegalStateException refused = assertThrows(IllegalStateException.class,
                Checkpoint::wipeAll);

        assertEquals(1, fine.wiped.get(), "a failure elsewhere spared this cache");
        assertTrue(refused.getSuppressed().length >= 1);
        failing.fail = false;                    // so that other tests' wipeAll is not refused
    }
}
