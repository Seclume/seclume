package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The statements the pool lends write every method of their interface out,
 * and each must hand its call on to the driver's statement: the same method,
 * the same arguments, the driver's answer back. Written out by hand, one
 * could call a neighbour - setInt handing on to setLong, getString(String)
 * to getString(int) - and nothing else would notice. Only getConnection()
 * answers otherwise: the pool's handle.
 */
class HandedDelegationTest {

    /** One call that reached the driver's statement. */
    private record Call(Method method, Object[] arguments) {
    }

    @Test
    void everyMethodOfAStatementReachesTheDriversStatement() throws Exception {
        check(Statement.class, (driver, handle) -> new HandedStatement(driver, handle));
    }

    @Test
    void everyMethodOfAPreparedStatementReachesTheDriversStatement() throws Exception {
        check(PreparedStatement.class,
                (driver, handle) -> new HandedPreparedStatement(driver, handle));
    }

    @Test
    void everyMethodOfACallableStatementReachesTheDriversStatement() throws Exception {
        check(CallableStatement.class,
                (driver, handle) -> new HandedCallableStatement(driver, handle));
    }

    private interface Wrapping<S extends Statement> {
        S wrap(S driver, Connection handle);
    }

    private static <S extends Statement> void check(Class<S> type, Wrapping<S> wrapping)
            throws Exception {
        List<Call> calls = new ArrayList<>();
        S driver = type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                (self, method, arguments) -> {
                    calls.add(new Call(method, arguments == null ? new Object[0] : arguments));
                    return answer(method.getReturnType());
                }));
        Connection handle = (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (self, method, arguments) -> null);
        S handed = wrapping.wrap(driver, handle);
        assertSame(handle, handed.getConnection(), "getConnection() is the pool's handle");
        assertTrue(calls.isEmpty(), "getConnection() asked the driver's statement");

        int checked = 0;
        for (Method method : type.getMethods()) {
            if (Modifier.isStatic(method.getModifiers()) || method.getName().equals("getConnection")) {
                continue;
            }
            Object[] arguments = arguments(method.getParameterTypes());
            calls.clear();
            Object answered;
            try {
                answered = handed.getClass().getMethod(method.getName(), method.getParameterTypes())
                        .invoke(handed, arguments);
            } catch (InvocationTargetException e) {
                throw new AssertionError(describe(method) + " threw", e.getCause());
            }
            assertEquals(1, calls.size(), describe(method) + " asked the driver "
                    + calls.size() + " times");
            Call call = calls.get(0);
            assertEquals(method.getName(), call.method().getName(), describe(method)
                    + " handed on to " + describe(call.method()));
            assertTrue(Arrays.equals(method.getParameterTypes(),
                    call.method().getParameterTypes()), describe(method) + " handed on to "
                    + describe(call.method()));
            assertTrue(Arrays.deepEquals(arguments, call.arguments()), describe(method)
                    + " changed its arguments: " + Arrays.deepToString(call.arguments()));
            assertEquals(answer(method.getReturnType()), answered, describe(method)
                    + " did not return the driver's answer");
            checked++;
        }
        assertTrue(checked > 40, "only " + checked + " methods were checked");
    }

    /** Arguments no two parameters of one method share where it matters: each its own value. */
    private static Object[] arguments(Class<?>[] types) {
        Object[] values = new Object[types.length];
        for (int i = 0; i < types.length; i++) {
            values[i] = value(types[i], i);
        }
        return values;
    }

    private static Object value(Class<?> type, int position) {
        if (type == int.class) {
            return 11 + position;
        }
        if (type == long.class) {
            return 21L + position;
        }
        if (type == boolean.class) {
            return position % 2 == 0;
        }
        if (type == double.class) {
            return 1.5 + position;
        }
        if (type == float.class) {
            return 2.5f + position;
        }
        if (type == short.class) {
            return (short) (31 + position);
        }
        if (type == byte.class) {
            return (byte) (41 + position);
        }
        if (type == String.class) {
            return "argument-" + position;
        }
        if (type == Class.class) {
            return Object.class;
        }
        if (type == int[].class) {
            return new int[] {position};
        }
        if (type == String[].class) {
            return new String[] {"column-" + position};
        }
        if (type == byte[].class) {
            return new byte[] {(byte) position};
        }
        if (type == Map.class) {
            return Map.of();
        }
        return null;
    }

    /** What the stand-in for the driver answers: a value of each type that can be told apart. */
    private static Object answer(Class<?> type) {
        if (type == int.class) {
            return 42;
        }
        if (type == long.class) {
            return 43L;
        }
        if (type == boolean.class) {
            return true;
        }
        if (type == double.class) {
            return 4.25;
        }
        if (type == float.class) {
            return 5.25f;
        }
        if (type == short.class) {
            return (short) 44;
        }
        if (type == byte.class) {
            return (byte) 45;
        }
        if (type == String.class) {
            return "the driver's answer";
        }
        return null;
    }

    private static String describe(Method method) {
        return method.getName() + Arrays.toString(Arrays.stream(method.getParameterTypes())
                .map(Class::getSimpleName).toArray());
    }
}
