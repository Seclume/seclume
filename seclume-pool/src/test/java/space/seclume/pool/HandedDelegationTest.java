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
        for (boolean yes : new boolean[] {true, false}) {
            check(type, wrapping, yes);
        }
    }

    /** One round: the driver answers each boolean with {@code yes}, and everything else with its own object. */
    private static <S extends Statement> void check(Class<S> type, Wrapping<S> wrapping,
                                                    boolean yes) throws Exception {
        List<Call> calls = new ArrayList<>();
        Map<Method, Object> answers = new java.util.HashMap<>();
        S driver = type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                (self, method, arguments) -> {
                    calls.add(new Call(method, arguments == null ? new Object[0] : arguments));
                    return answers.computeIfAbsent(method, m -> answer(m.getReturnType(), yes));
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
            Object expected = answers.get(call.method());
            if (method.getReturnType().isPrimitive()) {
                assertEquals(expected, answered, describe(method)
                        + " did not return the driver's answer");
            } else {
                assertSame(expected, answered, describe(method)
                        + " did not return the driver's answer");
            }
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

    /**
     * What the stand-in for the driver answers: for a boolean {@code yes}, for
     * another primitive a value no default is, for a reference an object of
     * its own - so that a wrapper that answered null, true or false, or zero,
     * instead of handing the driver's answer on, is caught.
     */
    private static Object answer(Class<?> type, boolean yes) {
        if (type == void.class) {
            return null;
        }
        if (type == boolean.class) {
            return yes;
        }
        if (type.isInterface()) {
            return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                    (self, method, arguments) -> switch (method.getName()) {
                        case "hashCode" -> System.identityHashCode(self);
                        case "equals" -> self == arguments[0];
                        case "toString" -> "answer of the driver";
                        default -> null;
                    });
        }
        if (type.isArray()) {
            return java.lang.reflect.Array.newInstance(type.getComponentType(), 1);
        }
        if (type == Object.class) {
            return new Object();
        }
        if (type == String.class) {
            return new String("the driver's answer".toCharArray());
        }
        if (type == java.math.BigDecimal.class) {
            return new java.math.BigDecimal("12.5");
        }
        if (type == java.io.Reader.class) {
            return new java.io.StringReader("the driver's answer");
        }
        if (type == java.net.URL.class) {
            try {
                return java.net.URI.create("https://example.org/answer").toURL();
            } catch (java.net.MalformedURLException e) {
                throw new IllegalStateException(e);
            }
        }
        if (type == java.sql.Date.class) {
            return new java.sql.Date(86_400_000L);
        }
        if (type == java.sql.Time.class) {
            return new java.sql.Time(3_600_000L);
        }
        if (type == java.sql.Timestamp.class) {
            return new java.sql.Timestamp(1_000_000L);
        }
        if (type == java.sql.SQLWarning.class) {
            return new java.sql.SQLWarning("the driver's answer");
        }
        if (type == int.class) {
            return 42;
        }
        if (type == long.class) {
            return 43L;
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
        throw new IllegalArgumentException("no answer of type " + type);
    }

    private static String describe(Method method) {
        return method.getName() + Arrays.toString(Arrays.stream(method.getParameterTypes())
                .map(Class::getSimpleName).toArray());
    }
}
