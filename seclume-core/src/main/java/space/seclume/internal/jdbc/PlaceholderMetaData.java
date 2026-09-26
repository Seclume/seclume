package space.seclume.internal.jdbc;

import java.sql.ParameterMetaData;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;

/**
 * {@code getParameterMetaData()} as far as it can be answered without asking
 * the server: how many parameters there are, and nothing seclume would have
 * to guess.
 *
 * <p>The count is what tools read - a query editor sizing its input form, a
 * mapper checking it has a value for every placeholder - and it is known from
 * the statement text alone. The types are not: seclume encodes each parameter
 * from the Java value it is given and never asks the server to describe them,
 * which would cost a round trip per statement for an answer nearly nobody
 * reads. So the type questions are refused, saying so; Spring's
 * {@code setNull}, the one well-known reader, catches that and uses the type
 * it was given.
 */
public final class PlaceholderMetaData implements ParameterMetaData {

    private final int count;
    private final boolean call;

    private PlaceholderMetaData(int count, boolean call) {
        this.count = count;
        this.call = call;
    }

    /** The parameters of a prepared statement: every one of them is IN. */
    public static ParameterMetaData of(int count) {
        return new PlaceholderMetaData(count, false);
    }

    /** The parameters of a call, whose modes are the procedure's business. */
    public static ParameterMetaData ofCall(int count) {
        return new PlaceholderMetaData(count, true);
    }

    /** The parameters of a statement text, counted as the drivers count them. */
    public static ParameterMetaData ofText(String sql) {
        return of(CallSyntax.placeholders(sql));
    }

    @Override
    public int getParameterCount() {
        return count;
    }

    @Override
    public int getParameterMode(int param) throws SQLException {
        check(param);
        return call ? parameterModeUnknown : parameterModeIn;
    }

    @Override
    public int isNullable(int param) throws SQLException {
        check(param);
        return parameterNullableUnknown;
    }

    @Override
    public int getParameterType(int param) throws SQLException {
        throw notDescribed(param);
    }

    @Override
    public String getParameterTypeName(int param) throws SQLException {
        throw notDescribed(param);
    }

    @Override
    public String getParameterClassName(int param) throws SQLException {
        throw notDescribed(param);
    }

    @Override
    public boolean isSigned(int param) throws SQLException {
        throw notDescribed(param);
    }

    @Override
    public int getPrecision(int param) throws SQLException {
        throw notDescribed(param);
    }

    @Override
    public int getScale(int param) throws SQLException {
        throw notDescribed(param);
    }

    private void check(int param) throws SQLException {
        if (param < 1 || param > count) {
            throw new SQLException("parameter " + param + " is out of range 1.." + count,
                    "07009");
        }
    }

    private SQLException notDescribed(int param) throws SQLException {
        check(param);
        return new SQLFeatureNotSupportedException("seclume does not ask the server to "
                + "describe parameters - it encodes each from the Java value it is given - so "
                + "the type of parameter " + param + " is not known here");
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        throw new SQLException("not a wrapper for " + iface.getName());
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
        return iface.isInstance(this);
    }
}
