package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * A plain query prepared with {@code prepareCall}: every method a prepared
 * statement has reaches the query with the arguments it was given, and every
 * method only a call has - its OUT parameters, its parameters by name - is
 * refused. Checked for each method of the interface, so that none is missing
 * and none answers with a made-up value.
 */
class QueryAsCallableTest {

    private record Seen(Method method, Object[] arguments) {
    }

    @Test
    void everyMethodIsDelegatedOrRefused() throws Exception {
        List<Seen> seen = new ArrayList<>();
        Object[] answer = new Object[1];
        PreparedStatement query = (PreparedStatement) Proxy.newProxyInstance(
                PreparedStatement.class.getClassLoader(), new Class<?>[] {PreparedStatement.class},
                (proxy, method, arguments) -> {
                    seen.add(new Seen(method, arguments));
                    return answer[0];
                });
        try (QueryAsCallable call = new QueryAsCallable(query)) {
            assertSame(query, call.query());

            int delegated = 0;
            int refused = 0;
            for (Method method : CallableStatement.class.getMethods()) {
                if (Modifier.isStatic(method.getModifiers())) {
                    continue;
                }
                Object[] arguments = Arrays.stream(method.getParameterTypes())
                        .map(QueryAsCallableTest::some).toArray();
                answer[0] = some(method.getReturnType());
                seen.clear();
                boolean onlyACallHasIt = !has(PreparedStatement.class, method);
                try {
                    Object result = method.invoke(call, arguments);
                    if (onlyACallHasIt) {
                        fail(method + " is only a call's, and answered " + result);
                    }
                    assertEquals(1, seen.size(), method + " reaches the query once");
                    assertEquals(method.getName(), seen.get(0).method().getName());
                    assertEquals(List.of(method.getParameterTypes()),
                            List.of(seen.get(0).method().getParameterTypes()), method.toString());
                    for (int i = 0; i < arguments.length; i++) {
                        if (method.getParameterTypes()[i].isPrimitive()) {
                            assertEquals(arguments[i], seen.get(0).arguments()[i],
                                    method + ", argument " + (i + 1));
                        } else {
                            assertSame(arguments[i], seen.get(0).arguments()[i],
                                    method + ", argument " + (i + 1));
                        }
                    }
                    if (!method.getReturnType().isPrimitive()) {
                        assertSame(answer[0], result, method + " hands the query's answer back");
                    } else if (method.getReturnType() != void.class) {
                        assertEquals(answer[0], result, method + " hands the query's answer back");
                    }
                    delegated++;
                } catch (InvocationTargetException thrown) {
                    assertTrue(onlyACallHasIt, method + " is a prepared statement's and was refused: "
                            + thrown.getCause());
                    SQLFeatureNotSupportedException reason = assertInstanceOf(
                            SQLFeatureNotSupportedException.class, thrown.getCause(), method.toString());
                    assertNotNull(reason.getMessage());
                    assertTrue(reason.getMessage().contains("OUT parameters"), reason.getMessage());
                    assertTrue(seen.isEmpty(), method + " was refused and still reached the query");
                    refused++;
                }
            }
            assertTrue(delegated > 80, "methods of a prepared statement: " + delegated);
            assertTrue(refused > 100, "methods only a call has: " + refused);
        }
    }

    private static boolean has(Class<?> type, Method method) {
        try {
            type.getMethod(method.getName(), method.getParameterTypes());
            return true;
        } catch (NoSuchMethodException none) {
            return false;
        }
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
            return java.lang.reflect.Array.newInstance(type.getComponentType(), 1);
        }
        if (type.isInterface()) {
            return Proxy.newProxyInstance(type.getClassLoader() == null
                    ? QueryAsCallableTest.class.getClassLoader() : type.getClassLoader(),
                    new Class<?>[] {type}, (proxy, method, arguments) -> null);
        }
        return null;
    }
}
