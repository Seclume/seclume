package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import space.seclume.ServerCapacity.Capacity;

/** When the pool warns about the server's connection limit, and when it keeps quiet. */
class CapacityWarningTest {

    @Test
    void aPoolThatCouldFillTheServerAloneIsWarnedAbout() {
        String warning = SeclumePool.capacityWarning("orders", 50, new Capacity(100, 70));
        assertTrue(warning.contains("this pool alone can exhaust the server"), warning);
        assertTrue(warning.contains("allows 100 with 70 in use"), warning);
    }

    @Test
    void roomForOnlyOneInstanceIsWarnedAbout() {
        String warning = SeclumePool.capacityWarning("orders", 20, new Capacity(100, 70));
        assertTrue(warning.contains("1 instance(s)"), warning);
    }

    @Test
    void roomForSeveralInstancesAndUnknownNumbersStayQuiet() {
        assertNull(SeclumePool.capacityWarning("orders", 10, new Capacity(200, 20)));
        assertNull(SeclumePool.capacityWarning("orders", 10, new Capacity(-1, -1)));
        assertNull(SeclumePool.capacityWarning("orders", 10, new Capacity(100, -1)));
    }
}
