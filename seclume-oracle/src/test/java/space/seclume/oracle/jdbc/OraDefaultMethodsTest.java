package space.seclume.oracle.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;
import java.sql.CallableStatement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * JDBC 4.2 added methods with a body that throws "not implemented". A class
 * that leaves one out compiles, and refuses the call at run time - as
 * {@code executeLargeUpdate()} of a callable statement did. Each of them is
 * written out in the driver.
 */
class OraDefaultMethodsTest {

    /** The defaults whose body refuses the call. */
    private static final Set<String> REFUSING = Set.of("executeLargeUpdate", "executeLargeBatch",
            "getLargeUpdateCount", "getLargeMaxRows", "setLargeMaxRows", "setObject",
            "registerOutParameter");

    @Test
    void noRefusingDefaultIsLeftToTheInterface() {
        List<String> left = new ArrayList<>();
        for (Method wanted : CallableStatement.class.getMethods()) {
            if (!wanted.isDefault() || !REFUSING.contains(wanted.getName())) {
                continue;
            }
            try {
                Method found = OraCallableStatement.class.getMethod(wanted.getName(),
                        wanted.getParameterTypes());
                if (found.getDeclaringClass().isInterface()
                        && found.getDeclaringClass().getName().startsWith("java.sql.")) {
                    left.add(found.toString());
                }
            } catch (NoSuchMethodException impossible) {
                left.add(wanted.toString());
            }
        }
        assertEquals(List.of(), left);
    }
}
