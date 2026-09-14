package space.seclume.oracle.jdbc;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Leaves the test schema as it was found.
 *
 * <p>Not tidiness. The Oracle tests drop their tables <em>before</em> creating
 * them, never after, so after a run something is always left standing - and
 * Flyway then refuses to migrate with „Found non-empty schema", which fails
 * eight Spring Data tests with a message that names neither the table nor the
 * test that left it. That cost an afternoon once.
 *
 * <p>Two details that make the difference between working and looking as if it
 * worked: {@code purge}, because a dropped table otherwise sits in the recycle
 * bin and still counts as an object; and dropping only what these tests create,
 * so a shared schema does not lose anything else.
 */
final class OracleTestSchema {

    private OracleTestSchema() {
    }

    /** Drops every table these tests create, and empties the recycle bin. */
    static void clean(Connection connection) throws SQLException {
        List<String> tables = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     // By name, not by prefix. „Everything starting with ZL_"
                     // looked tidier and took the Spring Data fixture with it:
                     // its tables are called ZL_CUSTOMER and ZL_ORDER, Flyway
                     // then considered the schema migrated and created nothing,
                     // and Hibernate failed with „missing table [zl_customer]" -
                     // in a different module, one build step later.
                     //
                     // The XA tables keep the prefix because their names carry
                     // a random suffix; substr instead of like, because like
                     // would read the underscore as a wildcard.
                     "select table_name from user_tables "
                     + "where table_name in ('ZL_ARRAY', 'ZL_BIND', 'ZL_COMMIT', "
                     + "                     'ZL_JDBC', 'ZL_KEYS', 'ZL_LOB', "
                     + "                     'ZL_LOB_SAMPLE', 'ZL_PREPARED', "
                     + "                     'ZL_PROBE', 'ZL_T4', 'ZL_TEMPLOB') "
                     + "   or substr(table_name, 1, 3) = 'XA_'")) {
            while (rows.next()) {
                tables.add(rows.getString(1));
            }
        }
        for (String table : tables) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("drop table " + table + " cascade constraints purge");
            } catch (SQLException e) {
                // Gone already, or held by something - not worth failing a test over.
            }
        }
        try (Statement statement = connection.createStatement()) {
            statement.execute("purge recyclebin");
        } catch (SQLException e) {
            // Not every user may; the drops above did the important part.
        }
    }
}
