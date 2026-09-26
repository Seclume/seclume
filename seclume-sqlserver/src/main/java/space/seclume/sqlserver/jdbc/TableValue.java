package space.seclume.sqlserver.jdbc;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import space.seclume.sqlserver.tds.TdsBulk;

/**
 * A table-valued parameter: rows for a user-defined table type, sent as one
 * parameter.
 *
 * <pre>
 *   // create type dbo.order_lines as table (sku varchar(20), quantity int)
 *   statement = connection.prepareStatement(
 *           "insert into lines (sku, quantity) select sku, quantity from ?");
 *   statement.setObject(1, TableValue.of("dbo.order_lines", rows));
 *   statement.executeUpdate();
 * </pre>
 *
 * <p>Each column's type is taken from its first non-null value, as a
 * parameter's type is taken from its value, and the server converts it into
 * the table type's column on the way in; text goes as {@code nvarchar}. The
 * rows are copied when the value is made, so a list that changes afterwards
 * does not change what is sent.
 */
public final class TableValue {

    private final String schema;
    private final String name;
    private final List<TdsBulk.Column> columns;
    private final List<Object[]> rows;

    private TableValue(String schema, String name, List<TdsBulk.Column> columns,
                       List<Object[]> rows) {
        this.schema = schema;
        this.name = name;
        this.columns = columns;
        this.rows = rows;
    }

    /**
     * Rows for the table type {@code typeName} - {@code order_lines} or
     * {@code dbo.order_lines}, brackets allowed. Every row has as many values
     * as the type has columns, in its column order; no rows at all is an
     * empty table.
     */
    public static TableValue of(String typeName, Iterable<Object[]> rows) throws SQLException {
        String[] parts = parse(typeName);
        List<Object[]> copy = new ArrayList<>();
        int width = -1;
        for (Object[] row : rows) {
            if (width >= 0 && row.length != width) {
                throw new SQLException("row " + (copy.size() + 1) + " of the table value for "
                        + typeName + " has " + row.length + " values, the first had " + width,
                        "22023");
            }
            width = row.length;
            copy.add(row.clone());
        }
        List<TdsBulk.Column> columns = List.of();
        if (width > 0) {
            String[] names = new String[width];
            for (int c = 0; c < width; c++) {
                names[c] = "column " + (c + 1);
            }
            columns = TdsBulk.columns(names, copy, null);
            long number = 0;
            for (Object[] row : copy) {
                TdsBulk.check(columns, row, ++number);
            }
        }
        return new TableValue(parts[0], parts[1], columns, List.copyOf(copy));
    }

    /**
     * {@code [schema.]name}, each part a plain identifier or in brackets -
     * nothing else, because the name stands in the statement's declaration.
     */
    private static String[] parse(String typeName) throws SQLException {
        List<String> parts = new ArrayList<>();
        int at = 0;
        int length = typeName == null ? 0 : typeName.length();
        while (at < length) {
            StringBuilder part = new StringBuilder(); // seclume-allow: a type name, no secret
            if (typeName.charAt(at) == '[') {
                at++;
                while (true) {
                    if (at >= length) {
                        throw badName(typeName);
                    }
                    char c = typeName.charAt(at++);
                    if (c == ']') {
                        if (at < length && typeName.charAt(at) == ']') {
                            at++;
                        } else {
                            break;
                        }
                    }
                    part.append(c);
                }
            } else {
                while (at < length && typeName.charAt(at) != '.') {
                    char c = typeName.charAt(at++);
                    if (!Character.isLetterOrDigit(c) && c != '_' && c != '#' && c != '@'
                            && c != '$') {
                        throw badName(typeName);
                    }
                    part.append(c);
                }
            }
            if (part.isEmpty() || part.length() > 128) {
                throw badName(typeName);
            }
            parts.add(part.toString());
            if (at < length) {
                if (typeName.charAt(at) != '.' || at == length - 1) {
                    throw badName(typeName);
                }
                at++;
            }
        }
        if (parts.isEmpty() || parts.size() > 2) {
            throw badName(typeName);
        }
        return parts.size() == 1 ? new String[] {"", parts.get(0)}
                : new String[] {parts.get(0), parts.get(1)};
    }

    private static SQLException badName(String typeName) {
        return new SQLException("'" + typeName + "' is not a table type name - "
                + "expected type or schema.type, plain or in [brackets]", "42602");
    }

    /** The schema, empty for the default one. */
    public String schema() {
        return schema;
    }

    /** The type's own name. */
    public String name() {
        return name;
    }

    /** The rows, as they are sent. */
    public int size() {
        return rows.size();
    }

    List<TdsBulk.Column> columns() {
        return columns;
    }

    List<Object[]> rows() {
        return rows;
    }

    /** As it stands in the parameter declaration: {@code [dbo].[order_lines] READONLY}. */
    String declaration() {
        return (schema.isEmpty() ? "" : quote(schema) + ".") + quote(name) + " READONLY";
    }

    private static String quote(String identifier) {
        return "[" + identifier.replace("]", "]]") + "]";
    }

    /** The parameter: type info (TVP_TYPE_INFO) and value, as TdsParameters writes them. */
    void write(space.seclume.internal.WireBuffer out) {
        TdsBulk.writeTable(out, schema, name, columns, rows);
    }

    /** The two pieces TdsParameters needs, visible across the package line. */
    public static final class Wire {
        private Wire() {
        }

        public static String declaration(TableValue value) {
            return value.declaration();
        }

        public static void write(space.seclume.internal.WireBuffer out, TableValue value) {
            value.write(out);
        }
    }
}
