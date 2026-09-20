package space.seclume.diff;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import space.seclume.tck.TestHosts;

/**
 * What class each driver puts in an array, asked rather than assumed.
 *
 * <p>Not an assertion but a question. {@code getObject} on a scalar
 * {@code smallint} must return an {@code Integer} - JDBC 4.3, Appendix B,
 * table B-3 - and the differential run showed seclume returning a
 * {@code Short}. The same question arises for {@code smallint[]}, and the
 * specification says less about it. So this prints what both drivers actually
 * do, and the answer decides what the fix should be rather than a guess about
 * it.
 *
 * <p>It stays in the module because the question comes back with every new
 * element type.
 */
class ArrayElementProbe {

    @Test
    void whatBothDriversPutInAnArray() throws Exception {
        Path file = locate();
        Assumptions.assumeTrue(file != null, "no PostgreSQL password file");
        Assumptions.assumeTrue(reachable(), "no PostgreSQL");

        String seclumeUrl = "jdbc:seclume:postgresql://" + TestHosts.postgres() + ":"
                + TestHosts.postgresPort() + "/seclume_test?user=seclume_test"
                + "&provider=file&path=" + file.toString().replace('\\', '/');
        Properties vendor = new Properties();
        vendor.setProperty("user", "seclume_test");
        vendor.setProperty("password", Files.readString(file).trim());

        try (Connection mine = DriverManager.getConnection(seclumeUrl);
             Connection theirs = DriverManager.getConnection("jdbc:postgresql://"
                     + TestHosts.postgres() + ":" + TestHosts.postgresPort()
                     + "/seclume_test", vendor)) {

            for (String type : List.of("smallint", "integer", "bigint", "real",
                    "double precision", "numeric(10,2)", "boolean", "text")) {
                System.out.println(type
                        + "  seclume=" + elementClass(mine, type)
                        + "  pgjdbc=" + elementClass(theirs, type));
            }
        }
    }

    private static String elementClass(Connection connection, String type) {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select array[1,2]::" + type + "[] as a")) {
            rows.next();
            Object array = rows.getArray(1).getArray();
            Object first = java.lang.reflect.Array.get(array, 0);
            return array.getClass().getComponentType().getName()
                    + " holding " + (first == null ? "null" : first.getClass().getName());
        } catch (SQLException | RuntimeException e) {
            return "<" + e.getClass().getSimpleName() + ": " + e.getMessage() + ">";
        }
    }

    private static Path locate() {
        String name = TestHosts.postgresPasswordFile();
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean reachable() {
        try (java.net.Socket probe = new java.net.Socket()) {
            probe.connect(new java.net.InetSocketAddress(
                    TestHosts.postgres(), TestHosts.postgresPort()), 1000);
            return true;
        } catch (Exception unreachable) {
            return false;
        }
    }
}
