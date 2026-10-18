package space.seclume.r2dbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import io.r2dbc.spi.Parameter;
import io.r2dbc.spi.Result;
import io.r2dbc.spi.Statement;
import reactor.core.publisher.Flux;

/**
 * A statement with the database's own placeholders, run as a JDBC prepared
 * statement - parameters always as parameters, never in the text.
 *
 * <p>Each {@link #add()} closes one set of bindings; {@link #execute()} runs
 * every set in order and answers one {@link Result} per set, each to be
 * consumed before the next is read, as R2DBC asks.
 */
final class SeclumeStatement implements Statement {

    /** A bound null and its type, which JDBC's setNull wants as a SQL type. */
    private record Null(Class<?> type) {
    }

    private final Connection connection;
    private final Lane lane;
    private final Placeholders.Parsed parsed;
    private final List<Map<String, Object>> sets = new ArrayList<>();
    private Map<String, Object> current = new HashMap<>();
    private String[] generatedColumns;
    private int fetchSize;
    /** An add() with nothing bound after it - an error at execute(), as R2DBC asks. */
    private boolean trailingAdd;

    SeclumeStatement(Connection connection, Lane lane, String sql,
                     Placeholders.Dialect dialect) {
        if (sql == null) {
            throw new IllegalArgumentException("createStatement needs the statement's SQL text, and null was given");
        }
        this.connection = connection;
        this.lane = lane;
        this.parsed = Placeholders.parse(sql, dialect);
    }

    @Override
    public Statement add() {
        requireComplete();
        sets.add(current);
        current = new HashMap<>();
        trailingAdd = true;
        return this;
    }

    @Override
    public Statement bind(int index, Object value) {
        return bind(parsed.nameOf(index), value, true);
    }

    @Override
    public Statement bind(String name, Object value) {
        return bind(name, value, false);
    }

    @Override
    public Statement bindNull(int index, Class<?> type) {
        return bind(parsed.nameOf(index), new Null(requireType(type)), true);
    }

    @Override
    public Statement bindNull(String name, Class<?> type) {
        return bind(name, new Null(requireType(type)), false);
    }

    private static Class<?> requireType(Class<?> type) {
        if (type == null) {
            throw new IllegalArgumentException("bindNull(..., null) - the type of the null");
        }
        return type;
    }

    private Statement bind(String name, Object value, boolean exact) {
        if (name == null) {
            throw new IllegalArgumentException("bind(null, ...) - a parameter has a name");
        }
        if (value == null) {
            throw new IllegalArgumentException("bind(..., null) - R2DBC binds a null with bindNull");
        }
        Object plain = value instanceof Parameter parameter ? parameter.getValue() : value;
        if (plain != null && !(value instanceof Null) && !SqlTypes.bindable(plain)) {
            throw new IllegalArgumentException("a " + plain.getClass().getName()
                    + " cannot be bound - convert it to a type the database has");
        }
        trailingAdd = false;
        String key = exact ? name : normalised(name);
        if (!parsed.positions().containsKey(key)) {
            throw new java.util.NoSuchElementException("no parameter '" + name + "' in this statement - "
                    + "it has " + parsed.positions().keySet());
        }
        current.put(key, value instanceof Parameter parameter && parameter.getValue() != null
                ? parameter.getValue()
                : value instanceof Parameter parameter ? new Null(parameter.getType().getJavaType())
                : value);
        return this;
    }

    /** "$1", ":name", "@name" or "name" - as the parse recorded it. */
    private String normalised(String name) {
        if (parsed.positions().containsKey(name)) {
            return name;
        }
        String bare = name.startsWith(":") || name.startsWith("@") ? name.substring(1) : name;
        String lower = bare.toLowerCase(Locale.ROOT);
        if (parsed.positions().containsKey(lower)) {
            return lower;
        }
        if (parsed.positions().containsKey("$" + bare)) {
            return "$" + bare;
        }
        return name;
    }

    private void requireComplete() {
        if (current.size() != parsed.positions().size()) {
            List<String> missing = new ArrayList<>(parsed.positions().keySet());
            missing.removeAll(current.keySet());
            throw new IllegalStateException("not every parameter is bound - missing " + missing);
        }
    }

    @Override
    public Statement returnGeneratedValues(String... columns) {
        if (columns == null) {
            throw new IllegalArgumentException("returnGeneratedValues takes column names - pass none for every generated column, not null");
        }
        for (String column : columns) {
            if (column == null) {
                throw new IllegalArgumentException("returnGeneratedValues with a null column");
            }
        }
        this.generatedColumns = columns.clone();
        return this;
    }

    @Override
    public Statement fetchSize(int rows) {
        this.fetchSize = rows;
        return this;
    }

    @Override
    public Flux<Result> execute() {
        if (trailingAdd) {
            return Flux.error(new IllegalStateException("add() with nothing bound after it"));
        }
        if (parsed.compound() && parsed.positions().isEmpty() && generatedColumns == null) {
            return lane.call(this::runScript).flatMapMany(Flux::fromIterable);
        }
        if (!current.isEmpty() || sets.isEmpty()) {
            requireComplete();
            sets.add(current);
            current = new HashMap<>();
        }
        List<Map<String, Object>> toRun = List.copyOf(sets);
        sets.clear();
        return Flux.fromIterable(toRun).concatMap(set -> lane.call(() -> run(set)));
    }

    /**
     * Several statements in one text, without parameters: each result read
     * in full, because the next one closes it - see {@link MaterializedResult}.
     */
    private List<Result> runScript() throws SQLException {
        List<Result> results = new ArrayList<>();
        try (java.sql.Statement statement = connection.createStatement()) {
            boolean rows = statement.execute(parsed.sql());
            while (true) {
                if (rows) {
                    try (java.sql.ResultSet set = statement.getResultSet()) {
                        results.add(MaterializedResult.ofRows(set));
                    }
                } else {
                    long count = statement.getLargeUpdateCount();
                    if (count < 0) {
                        return results;
                    }
                    results.add(MaterializedResult.ofCount(count));
                }
                rows = statement.getMoreResults();
            }
        }
    }

    /** One set of bindings, on the lane. */
    private Result run(Map<String, Object> set) throws SQLException {
        PreparedStatement statement = generatedColumns == null
                ? connection.prepareStatement(parsed.sql())
                : generatedColumns.length == 0
                        ? connection.prepareStatement(parsed.sql(),
                                java.sql.Statement.RETURN_GENERATED_KEYS)
                        : connection.prepareStatement(parsed.sql(), generatedColumns);
        try {
            if (fetchSize > 0) {
                statement.setFetchSize(fetchSize);
            }
            for (Map.Entry<String, int[]> parameter : parsed.positions().entrySet()) {
                Object value = set.get(parameter.getKey());
                for (int position : parameter.getValue()) {
                    if (value instanceof Null bound) {
                        statement.setNull(position, SqlTypes.of(bound.type()));
                    } else {
                        statement.setObject(position, SqlTypes.jdbcValue(value));
                    }
                    // A Blob or Clob is a stream; read on this lane, which is
                    // a virtual thread and may wait for it.

                }
            }
            if (statement.execute()) {
                return SeclumeResult.ofRows(lane, statement, statement.getResultSet());
            }
            if (generatedColumns != null) {
                return SeclumeResult.ofRows(lane, statement, statement.getGeneratedKeys());
            }
            return SeclumeResult.ofCount(lane, statement, statement.getLargeUpdateCount());
        } catch (SQLException | RuntimeException e) {
            statement.close();
            throw e;
        }
    }
}
