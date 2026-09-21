package space.seclume.diff;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * What each driver sends for {@code setObject(i, null)}, asked rather than assumed.
 *
 * <p>The differential run stopped on SQL Server with "Implicit conversion from
 * data type nvarchar to varbinary is not allowed", raised by seclume's own
 * session. {@code setObject(index, null)} is legal JDBC and says nothing about
 * the type, so the driver has to choose one - and the choice decides whether
 * the statement works at all against a typed column.
 *
 * <p>Two possibilities and they need different answers: if mssql-jdbc gets the
 * same refusal, the harness is asking something no driver supports and should
 * use {@code setNull}. If mssql-jdbc succeeds, seclume has a real gap. Guessing
 * between those two would either hide a fault or invent one, so the question is
 * put to both drivers.
 */
class NullBindProbe {

    @Test
    void whatHappensOnANullBindIntoATypedColumn() throws Exception {
        Assumptions.assumeTrue(SqlServerDifferentialTest.locate() != null,
                "no .local-mssql-password");
        SqlServerDifferentialTest.findTheServer();

        for (String type : List.of("varbinary(32)", "int", "datetime2(6)",
                "uniqueidentifier")) {
            System.out.println(type
                    + "\n    seclume: " + bindNull(SqlServerDifferentialTest::seclume, type)
                    + "\n    vendor : " + bindNull(SqlServerDifferentialTest::vendor, type));
        }
    }

    @FunctionalInterface
    private interface Connect {
        Connection get() throws SQLException;
    }

    private static String bindNull(Connect connect, String type) {
        String table = "probe_null_bind";
        try (Connection connection = connect.get()) {
            try (Statement drop = connection.createStatement()) {
                drop.execute("drop table " + table);
            } catch (SQLException notThere) {
                // first run
            }
            try (Statement create = connection.createStatement()) {
                create.execute("create table " + table + " (c " + type + ")");
            }
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into " + table + " (c) values (?)")) {
                insert.setObject(1, null);
                insert.executeUpdate();
            }
            try (Statement drop = connection.createStatement()) {
                drop.execute("drop table " + table);
            }
            return "accepted";
        } catch (SQLException refused) {
            return "refused: " + refused.getMessage();
        }
    }
}
