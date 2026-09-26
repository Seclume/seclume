package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * JSON and VECTOR over more rows than one fetch brings, next to every other
 * kind of column, read like ojdbc reads them.
 *
 * <p>Their values arrive as locators that live only until the next fetch: a
 * result of a hundred rows or more answered ORA-24826 from its first row,
 * because seclume had fetched every block before the first value was read.
 * The cursor now gets a define that brings the values in the row. That
 * changes how every column of the row is framed - so the row here has a CLOB,
 * a BLOB, a LONG, a ROWID and the national and time types beside them, runs
 * through a Statement and a PreparedStatement, and runs three times, the
 * later ones on the cursor the define was given to.
 */
@Timeout(300)
class OracleValueLobTest {

    private static final String TABLE = "seclume_value_lob";

    @Test
    void manyRowsOfJsonAndVectorReadLikeOjdbc() throws Exception {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path secret = TypeCatalogTest.locate(".local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        try (Connection theirs = DriverManager.getConnection("jdbc:oracle:thin:@//" + host + ":"
                        + port + "/FREEPDB1", JsonFunctionTest.oracleVendor(secret));
             Connection mine = DriverManager.getConnection("jdbc:seclume:oracle://" + host + ":"
                     + port + "/FREEPDB1?user=seclume_test&provider=file&path="
                     + TypeCatalogTest.slash(secret))) {
            try (Statement statement = theirs.createStatement()) {
                statement.execute("drop table if exists " + TABLE);
                statement.execute("create table " + TABLE + " (id int, j json, c clob, b blob, "
                        + "n nvarchar2(20), num number(10,2), d date, r raw(4), "
                        + "t timestamp with time zone, v vector(3, float32), l long)");
                statement.execute("insert into " + TABLE + " select level, "
                        + "case when mod(level, 7) = 0 then null else json('{\"a\":' || level "
                        + "|| ', \"s\":\"Grüße\"}') end, to_clob('clob ' || level), "
                        + "hextoraw('ab'), n'Grüße ' || level, level + 0.5, "
                        + "date '2024-01-01' + level, hextoraw('0102'), "
                        + "timestamp '2024-02-29 13:14:15 +02:00', "
                        + "case when mod(level, 5) = 0 then null "
                        + "else to_vector('[' || level || ',2,3]') end, 'long ' || level "
                        + "from dual connect by level <= 1000");
            }
            try {
                String sql = "select id, j, c, n, num, d, r, t, v, rowid, l, "
                        + "dbms_lob.getlength(b) from " + TABLE + " where id <= ? order by id";
                List<String> expected = rows(theirs, sql);
                for (int run = 0; run < 3; run++) {
                    assertEquals(expected, rows(mine, sql), "PreparedStatement, run " + run);
                    List<String> plain = new ArrayList<>();
                    try (Statement statement = mine.createStatement();
                         ResultSet rows = statement.executeQuery(sql.replace("?", "1000"))) {
                        while (rows.next()) {
                            plain.add(row(rows));
                        }
                    }
                    assertEquals(expected, plain, "Statement, run " + run);
                }
            } finally {
                try (Statement statement = theirs.createStatement()) {
                    statement.execute("drop table if exists " + TABLE);
                }
            }
        }
    }

    private static List<String> rows(Connection connection, String sql) throws SQLException {
        List<String> rows = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, 1000);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    rows.add(row(result));
                }
            }
        }
        return rows;
    }

    private static String row(ResultSet rows) throws SQLException {
        StringBuilder text = new StringBuilder();
        for (int i = 1; i <= rows.getMetaData().getColumnCount(); i++) {
            text.append(rows.getString(i)).append(" | ");
        }
        return text.toString();
    }
}
