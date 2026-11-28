package space.seclume;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.LiveTls;

/**
 * Who opened a TLS connection still open is the first class outside
 * seclume's TLS and internal packages - what a refused checkpoint names.
 * Here, outside both, that is this test. Isolated: other tests count the
 * open connections.
 */
@Isolated
class LiveTlsOriginTest {

    @Test
    void theOpenerIsTheFirstClassOutsideSeclumesTlsAndInternals() {
        Object connection = new Object();
        LiveTls.opened(connection);
        try {
            assertTrue(LiveTls.origins().contains(LiveTlsOriginTest.class.getName()),
                    LiveTls.origins().toString());
            assertFalse(LiveTls.origins().stream().anyMatch(o -> o.startsWith("space.seclume.internal.")
                    || o.startsWith("space.seclume.tls.") || o.isEmpty()), LiveTls.origins().toString());
        } finally {
            LiveTls.released(connection);
        }
        assertFalse(LiveTls.origins().contains(LiveTlsOriginTest.class.getName()));
    }
}
