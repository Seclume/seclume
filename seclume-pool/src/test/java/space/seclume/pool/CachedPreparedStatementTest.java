package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * What {@code DelegationIsCompleteTest} counts, run: every method of the
 * handle reaches the statement once, with the arguments it was given, and
 * hands its answer back - and after {@code close()} every one of them is
 * refused without reaching it.
 */
class CachedPreparedStatementTest {

    private record Seen(Method method, Object[] arguments) {
    }

    /** A statement that records what reached it and answers with {@code answer[0]}. */
    private static PreparedStatement recording(List<Seen> seen, Object[] answer) {
        return (PreparedStatement) Proxy.newProxyInstance(
                PreparedStatement.class.getClassLoader(), new Class<?>[] {PreparedStatement.class},
                (proxy, method, arguments) -> {
                    seen.add(new Seen(method, arguments == null ? new Object[0] : arguments));
                    if (method.getName().equals("isClosed")) {
                        return false;
                    }
                    return answer[0] == null && method.getReturnType().isPrimitive()
                            ? some(method.getReturnType()) : answer[0];
                });
    }

    /** Decided by the handle itself, not passed on as they are. */
    private static final Set<String> OWN = Set.of("close", "isClosed", "getConnection");

    @Test
    void everyMethodReachesTheStatementWithItsArgumentsAndItsAnswer() throws Exception {
        int checked = 0;
        for (Method method : PreparedStatement.class.getMethods()) {
            if (Modifier.isStatic(method.getModifiers()) || OWN.contains(method.getName())) {
                continue;
            }
            List<Seen> seen = new ArrayList<>();
            Object[] answer = {some(method.getReturnType())};
            PreparedStatement handle = CachedPreparedStatement.wrap(new StatementCache(4),
                    "select 1", recording(seen, answer), null);
            Object[] arguments = arguments(method);
            Object result;
            try {
                result = method.invoke(handle, arguments);
            } catch (InvocationTargetException thrown) {
                throw new AssertionError(method + " failed", thrown.getCause());
            }
            assertEquals(1, seen.size(), method + " reached the statement " + seen.size() + " times");
            Seen call = seen.get(0);
            assertEquals(method.getName(), call.method().getName(), method.toString());
            assertEquals(List.of(method.getParameterTypes()),
                    List.of(call.method().getParameterTypes()), method + " went to another overload");
            for (int i = 0; i < arguments.length; i++) {
                if (method.getParameterTypes()[i].isPrimitive()) {
                    assertEquals(arguments[i], call.arguments()[i], method + ", argument " + (i + 1));
                } else {
                    assertSame(arguments[i], call.arguments()[i], method + ", argument " + (i + 1));
                }
            }
            if (method.getReturnType().isPrimitive()) {
                if (method.getReturnType() != void.class) {
                    assertEquals(answer[0], result, method + " changed the statement's answer");
                }
            } else {
                assertSame(answer[0], result, method + " changed the statement's answer");
            }
            checked++;
        }
        assertTrue(checked > 100, "methods checked: " + checked);
    }

    @Test
    void afterCloseEveryMethodIsRefusedWithoutReachingTheStatement() throws Exception {
        int checked = 0;
        for (Method method : PreparedStatement.class.getMethods()) {
            if (Modifier.isStatic(method.getModifiers())
                    || method.getName().equals("close") || method.getName().equals("isClosed")) {
                continue;
            }
            List<Seen> seen = new ArrayList<>();
            PreparedStatement handle = CachedPreparedStatement.wrap(new StatementCache(4),
                    "select 1", recording(seen, new Object[] {null}), null);
            handle.close();
            seen.clear();
            try {
                method.invoke(handle, arguments(method));
                fail(method + " worked on a closed handle");
            } catch (InvocationTargetException thrown) {
                SQLException refused = (SQLException) thrown.getCause();
                assertEquals("HY010", refused.getSQLState(), method.toString());
            }
            assertEquals(List.of(), seen, method + " reached the statement after close()");
            checked++;
        }
        assertTrue(checked > 100, "methods checked: " + checked);
    }

    /**
     * A statement the cache did not prepare - or one a cache of no capacity
     * cannot keep - is closed when its handle is, once however often the
     * handle is closed.
     */
    @Test
    void aStatementTheCacheDoesNotKeepIsClosedOnce() throws Exception {
        for (int capacity : new int[] {0, 4}) {
            List<Seen> seen = new ArrayList<>();
            PreparedStatement handle = CachedPreparedStatement.wrap(new StatementCache(capacity),
                    "select 1", recording(seen, new Object[] {null}), null);
            assertFalse(handle.isClosed());
            handle.close();
            handle.close();
            assertTrue(handle.isClosed());
            assertEquals(1, seen.stream().filter(call -> call.method().getName().equals("close"))
                    .count(), "capacity " + capacity + ": " + seen);
        }
    }

    /** The statement outlives its borrower; the connection it names is the handle it came through. */
    @Test
    void getConnectionIsTheHandleItWasTakenThrough() throws Exception {
        List<Seen> seen = new ArrayList<>();
        Connection underneath = (Connection) some(Connection.class);
        Connection handle = (Connection) some(Connection.class);
        PreparedStatement through = CachedPreparedStatement.wrap(new StatementCache(4), "select 1",
                recording(seen, new Object[] {underneath}), handle);
        assertSame(handle, through.getConnection());
        PreparedStatement without = CachedPreparedStatement.wrap(new StatementCache(4), "select 1",
                recording(seen, new Object[] {underneath}), null);
        assertSame(underneath, without.getConnection());
        through.close();
        assertThrows(SQLException.class, through::getConnection);
    }

    private static Object[] arguments(Method method) {
        Class<?>[] types = method.getParameterTypes();
        Object[] arguments = new Object[types.length];
        for (int i = 0; i < types.length; i++) {
            arguments[i] = types[i] == int.class ? (Object) (i + 2) : some(types[i]);
        }
        return arguments;
    }

    /** A value of {@code type}: distinct objects where one can be made, so that they are told apart. */
    private static Object some(Class<?> type) {
        if (type == void.class) {
            return null;
        }
        if (type == boolean.class) {
            return true;
        }
        if (type == byte.class) {
            return (byte) 3;
        }
        if (type == short.class) {
            return (short) 4;
        }
        if (type == int.class) {
            return 5;
        }
        if (type == long.class) {
            return 6L;
        }
        if (type == float.class) {
            return 7f;
        }
        if (type == double.class) {
            return 8d;
        }
        if (type == String.class) {
            return "text";
        }
        if (type == Class.class) {
            return Object.class;
        }
        if (type.isArray()) {
            return Array.newInstance(type.getComponentType(), 1);
        }
        if (type.isInterface()) {
            return Proxy.newProxyInstance(CachedPreparedStatementTest.class.getClassLoader(),
                    new Class<?>[] {type}, (proxy, method, arguments) -> null);
        }
        return null;
    }
}
