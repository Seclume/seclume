package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Every method of the interface is written out, and this is what makes that
 * safe.
 *
 * <p>{@code CachedPreparedStatement} used to be a dynamic proxy, for a good
 * reason stated in its own comment: {@code PreparedStatement} has a hundred
 * methods, and one left out would send a call quietly to a statement the
 * caller believes is closed - no exception, no log line, the wrong object.
 *
 * <p>It is a written-out class now, and the reason first given for that was
 * wrong: a native image does <b>not</b> need a proxy registered when the
 * interface is a class literal, which was measured rather than assumed - see
 * the roadmap for 22.09.2026. The change stands on what it actually buys.
 * <b>The reason for the proxy did not go away; it moved into the compiler</b>,
 * which refuses a concrete class with a method missing. What is left for a test
 * is the half javac cannot see: that every one of those methods goes through
 * the guard, and that a closed handle really refuses.
 *
 * <p>Reflection in a test is not the reflection the native image objects to:
 * nothing here is shipped, and no image is built from a test.
 */
class DelegationIsCompleteTest {

    @Test
    void everyMethodOfPreparedStatementIsOverridden() {
        List<String> missing = new ArrayList<>();
        for (Method wanted : PreparedStatement.class.getMethods()) {
            if (wanted.isDefault() || Modifier.isStatic(wanted.getModifiers())) {
                continue;
            }
            try {
                Method found = CachedPreparedStatement.class
                        .getDeclaredMethod(wanted.getName(), wanted.getParameterTypes());
                assertTrue(found != null);
            } catch (NoSuchMethodException absent) {
                missing.add(wanted.getName() + Arrays.toString(wanted.getParameterTypes())
                        .replace("class ", "").replace("interface ", ""));
            }
        }
        assertEquals(List.of(), missing,
                "these calls would go straight to the wrapped statement, including after "
                + "the handle was closed - which is the failure this class exists to "
                + "prevent and the reason it used to be a proxy");
    }

    /**
     * And the guard is in every one of them.
     *
     * <p>Counting rather than reading: a delegating method that forgot
     * {@code open()} would be a method that works on a closed handle. The two
     * that deliberately do not call it are {@code close} and {@code isClosed},
     * which have to work afterwards.
     */
    @Test
    void everyDelegatingMethodGoesThroughTheGuard() throws Exception {
        String source = java.nio.file.Files.readString(java.nio.file.Path.of(
                "src/main/java/space/seclume/pool/CachedPreparedStatement.java"));
        int overrides = source.split("@Override", -1).length - 1;
        int guarded = source.split("open\\(\\)\\.", -1).length - 1;
        assertEquals(overrides - 2, guarded,
                "every overridden method but close and isClosed has to go through open(): "
                + overrides + " overrides, " + guarded + " guarded");
    }

    /** A closed handle refuses, and says so the way JDBC does. */
    @Test
    void aClosedHandleRefuses() throws Exception {
        // A statement that does nothing, made with a proxy - which is exactly
        // what the class under test no longer is, and is fine here: a test is
        // not shipped and no image is built from one.
        PreparedStatement nothing = (PreparedStatement) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {PreparedStatement.class},
                (proxy, method, args) -> method.getReturnType() == boolean.class
                        ? Boolean.FALSE : null);
        StatementCache cache = new StatementCache(4);
        PreparedStatement handle = CachedPreparedStatement.wrap(cache, "select 1", nothing);
        handle.close();
        assertTrue(handle.isClosed(), "a closed handle should say it is closed");
        SQLException refused = org.junit.jupiter.api.Assertions.assertThrows(
                SQLException.class, handle::executeQuery);
        assertEquals("HY010", refused.getSQLState(),
                "the refusal should be the state JDBC uses for a closed object");
    }
}
