package space.seclume.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * A log emptied by someone who can write the file has no entry left
 * unsigned and nothing wrong in it - and no signature either. The key
 * vouches for nothing there: one checkpoint that held is the least.
 */
class EmptyLogVouchTest {

    @Test
    void anEmptyLogIsNotVouchedFor() {
        AccessLogVerifier.Result empty = new AccessLogVerifier.Result(1, 0, 0, 0,
                AccessLog.ZERO, List.of());
        assertTrue(empty.holds());
        assertEquals(0, empty.unsigned());
        assertFalse(empty.vouched(), "a log without one checkpoint was vouched for");
        // The control: one checkpoint over the one entry.
        assertTrue(new AccessLogVerifier.Result(1, 1, 1, 1, AccessLog.ZERO, List.of()).vouched());
    }
}
