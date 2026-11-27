package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * seclume.oracle.traceLob writes LOB contents to System.err. Alone it is
 * ignored - with a notice saying so - and only together with
 * seclume.debug.unsafe=true does it trace.
 */
@Isolated
class TraceLobTest {

    private static boolean decided() throws Exception {
        Method traceLob = OracleSession.class.getDeclaredMethod("traceLob");
        traceLob.setAccessible(true);
        return (boolean) traceLob.invoke(null);
    }

    @Test
    void traceLobAloneIsIgnoredAndWithUnsafeItTraces() throws Exception {
        String trace = System.getProperty("seclume.oracle.traceLob");
        String unsafe = System.getProperty("seclume.debug.unsafe");
        try {
            System.clearProperty("seclume.oracle.traceLob");
            System.clearProperty("seclume.debug.unsafe");
            assertFalse(decided(), "traced without being asked");
            System.setProperty("seclume.oracle.traceLob", "true");
            assertFalse(decided(), "LOB contents traced without seclume.debug.unsafe");
            System.setProperty("seclume.debug.unsafe", "true");
            assertTrue(decided(), "both set, and still not traced");
        } finally {
            restore("seclume.oracle.traceLob", trace);
            restore("seclume.debug.unsafe", unsafe);
        }
    }

    private static void restore(String name, String value) {
        if (value == null) {
            System.clearProperty(name);
        } else {
            System.setProperty(name, value);
        }
    }
}
