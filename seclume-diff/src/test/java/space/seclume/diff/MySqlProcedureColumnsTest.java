package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * The corpus that did not exist: procedure parameters, both drivers.
 *
 * <p>{@code getProcedureColumns} reads a different catalogue view from
 * {@code getColumns} and a differently named column in it - the declaration is
 * {@code dtd_identifier} there and {@code column_type} here - so every rule
 * about MySQL's types has to be written twice and only one of the two was ever
 * checked. That is the shape of the defects this suite keeps finding: not a
 * rule that is wrong, a rule that exists in one place and not in its twin.
 *
 * <p>The parameters below are chosen for the places the two catalogues have
 * historically disagreed: {@code tinyint(1)}, which every ORM writes a boolean
 * into; the text family, where one type code covers four sizes; and a
 * {@code decimal}, where the width, the point and the sign have to be told
 * apart.
 */
@Timeout(300)
class MySqlProcedureColumnsTest {

    private static final String HOST = System.getProperty("seclume.mysql.host",
            TestHosts.database());
    private static final int PORT = Integer.getInteger("seclume.mysql.port", 3307);
    private static final String DATABASE = "seclume_test";
    private static final String USER = "seclume_test";
    private static final String PROCEDURE = "diff_my_proc";

    /** The fields both drivers have to agree about, by name. */
    private static final List<String> FIELDS = List.of(
            "COLUMN_NAME", "COLUMN_TYPE", "DATA_TYPE", "TYPE_NAME",
            "PRECISION", "SCALE", "RADIX", "ORDINAL_POSITION");

    private static String seclumeUrl;
    private static String vendorUrl;
    private static String password;

    @BeforeAll
    static void findTheServer() throws Exception {
        Path file = null;
        for (Path candidate : List.of(Path.of(".local-mysql-password"),
                Path.of("..", ".local-mysql-password"))) {
            if (Files.exists(candidate)) {
                file = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(file != null, "no .local-mysql-password");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("no MySQL on " + HOST + ":" + PORT);
        }
        seclumeUrl = "jdbc:seclume:mysql://" + HOST + ":" + PORT + "/" + DATABASE
                + "?user=" + USER + "&allowPublicKeyRetrieval=true&provider=file&path="
                + file.toString().replace(java.io.File.separatorChar, '/');
        vendorUrl = "jdbc:mysql://" + HOST + ":" + PORT + "/" + DATABASE;
        password = Files.readString(file).trim();
    }

    @AfterAll
    static void forgetIt() {
        password = null;
    }

    @Test
    void bothDriversDescribeTheSameParametersTheSameWay() throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            create(theirs);
            try {
                List<Map<String, String>> ours = describe(mine);
                List<Map<String, String>> vendors = describe(theirs);

                assertEquals(vendors.size(), ours.size(),
                        "a different number of parameters: seclume " + ours
                                + ", Connector/J " + vendors);
                assertTrue(!ours.isEmpty(), "neither driver found the procedure at all");

                List<String> differences = new ArrayList<>();
                for (int i = 0; i < ours.size(); i++) {
                    Map<String, String> a = ours.get(i);
                    Map<String, String> b = vendors.get(i);
                    for (String field : FIELDS) {
                        if (String.valueOf(a.get(field)).equals(String.valueOf(b.get(field)))) {
                            continue;
                        }
                        if (aNumberWhereTheVendorSaysNothing(field, a.get(field),
                                b.get(field))) {
                            continue;
                        }
                        differences.add(a.get("COLUMN_NAME") + "." + field
                                + "  seclume=" + a.get(field)
                                + "  vendor=" + b.get(field));
                    }
                }
                assertTrue(differences.isEmpty(),
                        () -> "seclume and Connector/J describe the same parameters "
                                + "differently:\n  " + String.join("\n  ", differences));
            } finally {
                drop(theirs);
            }
        }
    }

    /**
     * The one allowed difference, and it is a difference in kind.
     *
     * <p>For a character parameter Connector/J returns <b>null</b> for
     * {@code PRECISION} and {@code SCALE}; seclume returns the character count
     * and a zero. Not two answers to one question - one answer and a
     * declining to answer, and the caller that reads it with
     * {@code getInt} gets a zero from Connector/J either way.
     *
     * <p>Written narrowly on purpose: only where the vendor said nothing at
     * all and only for these two fields. A tolerance that accepted any
     * disagreement about a number would have hidden every finding this file
     * exists for, including the four it found on its first run.
     */
    private static boolean aNumberWhereTheVendorSaysNothing(String field, String ours,
            String vendors) {
        return vendors == null && ours != null
                && (field.equals("PRECISION") || field.equals("SCALE"));
    }

    /**
     * And the catalogue agrees with itself.
     *
     * <p>The same declaration read through {@code getColumns} and through
     * {@code getProcedureColumns} has to give the same type. Two views, two
     * column names, one rule - and the whole reason this file exists is that
     * the second copy of that rule had nothing checking it.
     */
    @Test
    void aParameterAndAColumnOfTheSameTypeAgree() throws Exception {
        try (Connection mine = seclume(); Connection theirs = vendor()) {
            create(theirs);
            try (Statement statement = theirs.createStatement()) {
                statement.execute("drop table if exists diff_my_proc_shape");
                statement.execute("create table diff_my_proc_shape ("
                        + "p_flag tinyint(1), p_note mediumtext, p_amount decimal(12,4))");
            }
            try {
                Map<String, String> byColumn = new LinkedHashMap<>();
                try (ResultSet rows = mine.getMetaData()
                        .getColumns(null, null, "diff_my_proc_shape", "%")) {
                    while (rows.next()) {
                        byColumn.put(rows.getString("COLUMN_NAME"),
                                rows.getInt("DATA_TYPE") + "/" + rows.getString("TYPE_NAME"));
                    }
                }
                List<String> differences = new ArrayList<>();
                for (Map<String, String> parameter : describe(mine)) {
                    String name = parameter.get("COLUMN_NAME");
                    String asColumn = byColumn.get(name);
                    if (asColumn == null) {
                        continue;
                    }
                    String asParameter = parameter.get("DATA_TYPE") + "/"
                            + parameter.get("TYPE_NAME");
                    if (!asColumn.equals(asParameter)) {
                        differences.add(name + "  as a column " + asColumn
                                + ", as a parameter " + asParameter);
                    }
                }
                assertTrue(differences.isEmpty(),
                        () -> "the two catalogues disagree about the same declaration:\n  "
                                + String.join("\n  ", differences));
            } finally {
                try (Statement statement = theirs.createStatement()) {
                    statement.execute("drop table if exists diff_my_proc_shape");
                }
                drop(theirs);
            }
        }
    }

    private static void create(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("drop procedure if exists " + PROCEDURE);
            statement.execute("create procedure " + PROCEDURE + "("
                    + "in p_flag tinyint(1), "
                    + "in p_small tinyint, "
                    + "in p_note mediumtext, "
                    + "in p_label varchar(40), "
                    + "in p_amount decimal(12,4), "
                    + "out p_count int) "
                    + "begin set p_count = 1; end");
        }
    }

    private static void drop(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("drop procedure if exists " + PROCEDURE);
        }
    }

    private static List<Map<String, String>> describe(Connection connection)
            throws SQLException {
        List<Map<String, String>> rows = new ArrayList<>();
        try (ResultSet found = connection.getMetaData()
                .getProcedureColumns(null, null, PROCEDURE, "%")) {
            while (found.next()) {
                Map<String, String> row = new LinkedHashMap<>();
                for (String field : FIELDS) {
                    row.put(field, found.getString(field));
                }
                rows.add(row);
            }
        }
        return rows;
    }

    private static Connection seclume() throws SQLException {
        return DriverManager.getConnection(seclumeUrl);
    }

    private static Connection vendor() throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", USER);
        properties.setProperty("password", password);
        properties.setProperty("allowPublicKeyRetrieval", "true");
        properties.setProperty("useSSL", "false");
        properties.setProperty("getProceduresReturnsFunctions", "false");
        return DriverManager.getConnection(vendorUrl, properties);
    }
}
