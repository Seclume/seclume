package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A whole list bound to one placeholder, {@code where x in (?)}, on all four:
 * every element type, {@code not in}, the empty list, more elements than SQL
 * Server's 2100 parameters and Oracle's 1000 list entries, and the refusals.
 */
@Timeout(120)
class InListTest {

    private static final UUID FIRST = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID SECOND = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final String AWKWARD = "b\"q'x\\ü,{}";

    static List<CapacityTest.Target> targets() {
        return CapacityTest.targets();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("targets")
    void aListBindsAsOneValue(CapacityTest.Target target) throws Exception {
        try (Connection c = open(target)) {
            table(c, target.name());
            try {
                assertEquals(2, count(c, "id in (?)", List.of(1, 3, 99)));
                assertEquals(2, count(c, "id in (?)", new Long[] {1L, 2L}));
                assertEquals(2, count(c, "name in (?)", List.of("a", AWKWARD, "zz")));
                assertEquals(2, count(c, "amount in (?)", List.of(new BigDecimal("1.5"), 2.25)));
                assertEquals(2, count(c, "uid_ in (?)", List.of(FIRST, SECOND)));
                assertEquals(1, count(c, "id not in (?)", List.of(1, 2)));
                assertEquals(0, count(c, "id in (?)", List.of()));
                assertEquals(3, count(c, "id NOT IN ( ? )", List.of()));

                List<Integer> many = new ArrayList<>();
                for (int i = 3; i < 5003; i++) {
                    many.add(i);
                }
                assertEquals(1, count(c, "id in (?)", many));

                // One statement, lists of every length, and ordinary values beside them.
                try (PreparedStatement s = c.prepareStatement(
                        "select count(*) from seclume_inlist where id in (?) and name <> ?")) {
                    for (List<Integer> ids : List.of(List.of(1), List.of(1, 2), List.of(1, 2, 3))) {
                        s.setObject(1, ids);
                        s.setString(2, "c");
                        assertEquals(Math.min(ids.size(), 2), one(s));
                    }
                }
                if (target.name().equals("PostgreSQL")) {
                    try (Statement s = c.createStatement();
                         ResultSet rows = s.executeQuery("select count(*) from "
                                 + "pg_prepared_statements where statement like '%and name <> $2%'")) {
                        rows.next();
                        assertEquals(1, rows.getInt(1), "one plan for every list length");
                    }
                }
            } finally {
                drop(c);
            }
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("targets")
    void aListWhereItCannotBeIsRefused(CapacityTest.Target target) throws Exception {
        try (Connection c = open(target);
             PreparedStatement s = c.prepareStatement(target.name().equals("Oracle")
                     ? "select 1 from dual where 1 = ?" : "select 1 where 1 = ?")) {
            s.setObject(1, List.of(1, 2));
            SQLException refused = assertThrows(SQLException.class, s::executeQuery);
            assertEquals("22023", refused.getSQLState(), refused.getMessage());
            List<Integer> withNull = new ArrayList<>();
            withNull.add(null);
            SQLException nulls = assertThrows(SQLException.class, () -> s.setObject(1, withNull));
            assertEquals("22004", nulls.getSQLState(), nulls.getMessage());
            s.setObject(1, List.of(1));
            SQLException batch = assertThrows(SQLException.class, s::addBatch);
            assertTrue(batch.getMessage().contains("batch"), batch.getMessage());
        }
    }

    private static Connection open(CapacityTest.Target target) throws Exception {
        Path secret = TypeCatalogTest.locate(target.secret());
        String address = target.url().substring(target.url().indexOf("//") + 2);
        TypeCatalogTest.reachable(address.substring(0, address.indexOf(':')),
                Integer.parseInt(address.substring(address.indexOf(':') + 1,
                        address.indexOf('/'))), secret);
        return DriverManager.getConnection(target.url()
                + "&provider=file&path=" + TypeCatalogTest.slash(secret));
    }

    private static void table(Connection c, String name) throws SQLException {
        drop(c);
        String uid = switch (name) {
            case "PostgreSQL" -> "uuid";
            case "SQL Server" -> "uniqueidentifier";
            case "Oracle" -> "varchar2(36)";
            default -> "char(36)";
        };
        try (Statement s = c.createStatement()) {
            s.execute(name.equals("Oracle")
                    ? "create table seclume_inlist (id number(10) primary key, name nvarchar2(40), "
                            + "amount number(12,2), uid_ " + uid + ")"
                    : "create table seclume_inlist (id int primary key, name "
                            + (name.equals("SQL Server") ? "nvarchar" : "varchar")
                            + "(40), amount decimal(12,2), uid_ " + uid + ")");
        }
        try (PreparedStatement s = c.prepareStatement(
                "insert into seclume_inlist values (?, ?, ?, ?)")) {
            Object[][] rows = {
                    {1, "a", new BigDecimal("1.50"), FIRST},
                    {2, AWKWARD, new BigDecimal("2.25"), SECOND},
                    {3, "c", new BigDecimal("3.00"), UUID.randomUUID()}};
            for (Object[] row : rows) {
                s.setInt(1, (Integer) row[0]);
                s.setString(2, (String) row[1]);
                s.setBigDecimal(3, (BigDecimal) row[2]);
                if (name.equals("PostgreSQL") || name.equals("SQL Server")) {
                    s.setObject(4, row[3]);
                } else {
                    s.setString(4, row[3].toString());
                }
                s.executeUpdate();
            }
        }
    }

    private static void drop(Connection c) {
        try (Statement s = c.createStatement()) {
            s.execute("drop table seclume_inlist");
        } catch (SQLException absent) {
            // not there yet
        }
    }

    private static int count(Connection c, String condition, Object list) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(
                "select count(*) from seclume_inlist where " + condition)) {
            s.setObject(1, list);
            return one(s);
        }
    }

    private static int one(PreparedStatement s) throws SQLException {
        try (ResultSet rows = s.executeQuery()) {
            rows.next();
            return rows.getInt(1);
        }
    }
}
