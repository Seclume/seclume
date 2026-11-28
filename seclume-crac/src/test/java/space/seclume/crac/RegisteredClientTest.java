package space.seclume.crac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.crac.Resource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * {@code register} took a {@link space.seclume.pool.SeclumePool} only. The
 * MongoDB, HTTP and Redis clients on seclume's TLS had no way to be told of a
 * checkpoint, and their open connections refused it. Any client can be
 * registered now - suspended and resumed, or closed.
 */
// Alone: the registrations are the whole JVM's.
@Isolated
class RegisteredClientTest {

    private static Resource last() {
        List<Resource> registered = SeclumeCrac.registered();
        return registered.get(registered.size() - 1);
    }

    @Test
    void aRegisteredClientIsSuspendedBeforeAndResumedAfter() throws Exception {
        List<String> calls = new ArrayList<>();
        SeclumeCrac.register(new SeclumeCrac.Suspendable() {
            @Override
            public void suspend() {
                calls.add("suspend");
            }

            @Override
            public void resume() {
                calls.add("resume");
            }
        });
        Resource resource = last();
        resource.beforeCheckpoint(null);
        resource.afterRestore(null);
        assertEquals(List.of("suspend", "resume"), calls);
    }

    @Test
    void aClientThatCannotLetGoRefusesTheCheckpoint() {
        SeclumeCrac.register(new SeclumeCrac.Suspendable() {
            @Override
            public void suspend() {
                throw new IllegalStateException("still busy");
            }

            @Override
            public void resume() {
            }
        });
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> last().beforeCheckpoint(null));
        assertEquals("still busy", refused.getMessage());
    }

    @Test
    void aClientToCloseIsClosedBeforeTheCheckpoint() throws Exception {
        boolean[] closed = new boolean[1];
        SeclumeCrac.closeBeforeCheckpoint(() -> closed[0] = true);
        Resource resource = last();
        resource.beforeCheckpoint(null);
        assertTrue(closed[0], "the client was not closed");
        resource.afterRestore(null);                    // nothing to do, and no failure
    }
}
