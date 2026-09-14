package space.seclume.pool;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * The handle an application holds on a cached statement.
 *
 * <p>JDBC says a closed statement is unusable, and the cache says the statement
 * lives on. Both are true at once because what the caller holds is not the
 * statement: it is a handle whose {@code close()} gives the statement back to
 * the cache and then refuses everything, exactly as a closed one would.
 *
 * <p>A proxy rather than a class with a hundred delegating methods - the same
 * reasoning as for the XA connection handle. {@code PreparedStatement} has too
 * many methods to write out without forgetting one, and forgetting one here
 * would mean a call quietly going to a statement the caller believes is closed.
 */
final class CachedPreparedStatement implements InvocationHandler {

    private final StatementCache cache;
    private final String sql;
    private final PreparedStatement statement;
    private boolean given;

    private CachedPreparedStatement(StatementCache cache, String sql,
                                    PreparedStatement statement) {
        this.cache = cache;
        this.sql = sql;
        this.statement = statement;
    }

    /** Wraps a statement so that closing it returns it to the cache. */
    static PreparedStatement wrap(StatementCache cache, String sql,
                                  PreparedStatement statement) {
        return (PreparedStatement) Proxy.newProxyInstance(
                CachedPreparedStatement.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class},
                new CachedPreparedStatement(cache, sql, statement));
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
        String name = method.getName();
        if ("close".equals(name)) {
            if (!given) {
                given = true;
                if (!cache.give(sql, statement)) {
                    statement.close();
                }
            }
            return null;
        }
        if ("isClosed".equals(name)) {
            return given || statement.isClosed();
        }
        if (given) {
            throw new SQLException("this prepared statement was closed", "HY010");
        }
        try {
            return method.invoke(statement, arguments);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }
}
