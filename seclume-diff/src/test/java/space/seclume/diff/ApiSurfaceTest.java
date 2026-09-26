package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * Every method of the JDBC interfaces an application touches, called through
 * seclume and through the vendor's driver: where the vendor does it and
 * seclume answers {@code SQLFeatureNotSupportedException}, that is a gap.
 *
 * <p>Found by hand before this existed: {@code closeOnCompletion} and
 * {@code setNetworkTimeout}, refused by all four while every vendor had them.
 * This finds the rest without anybody having to think of them. Each method is
 * called on a fresh object with plain arguments - a column index of 1, a label
 * the query has, zero, {@code null} - and only one outcome is compared: not
 * supported against anything else. Whether the arguments made sense for the
 * method is not the question; whether the method exists at all is.
 *
 * <p>What seclume refuses on purpose is listed in {@link #DECIDED} with the
 * reason. Anything else refused where the vendor is not fails.
 */
// Alone: thousands of logins in bursts - Oracle's listener turns the other
// classes' logins away meanwhile (ORA-12516).
@org.junit.jupiter.api.parallel.Isolated
@Timeout(900)
class ApiSurfaceTest {

    /** Refused on purpose, by method signature, on every driver. */
    private static final Map<String, String> DECIDED = new TreeMap<>(Map.ofEntries(
            Map.entry("ResultSet.update*", "read-only results: change data with UPDATE"),
            Map.entry("ResultSet.insertRow()", "read-only results"),
            Map.entry("ResultSet.updateRow()", "read-only results"),
            Map.entry("ResultSet.deleteRow()", "read-only results"),
            Map.entry("ResultSet.refreshRow()", "read-only results"),
            Map.entry("ResultSet.moveToInsertRow()", "read-only results"),
            Map.entry("ResultSet.moveToCurrentRow()", "read-only results"),
            Map.entry("ResultSet.cancelRowUpdates()", "read-only results"),
            Map.entry("ResultSet.rowUpdated()", "read-only results"),
            Map.entry("ResultSet.rowInserted()", "read-only results"),
            Map.entry("ResultSet.rowDeleted()", "read-only results"),
            Map.entry("ResultSet.getCursorName()", "no named cursors"),
            Map.entry("ResultSet.getUnicodeStream(int)", "deprecated since JDBC 2"),
            Map.entry("ResultSet.getUnicodeStream(String)", "deprecated since JDBC 2"),
            Map.entry("PreparedStatement.setUnicodeStream(int,InputStream,int)",
                    "deprecated since JDBC 2"),
            Map.entry("Connection.setTypeMap(Map)", "no user-defined types to map"),
            Map.entry("PreparedStatement.execute(String", "JDBC forbids the text-taking "
                    + "methods on a prepared statement; the vendors throw a plain SQLException"),
            Map.entry("PreparedStatement.executeUpdate(String", "the same"),
            Map.entry("PreparedStatement.executeLargeUpdate(String", "the same"),
            Map.entry("CallableStatement.execute(String", "the same"),
            Map.entry("CallableStatement.executeUpdate(String", "the same"),
            Map.entry("CallableStatement.executeLargeUpdate(String", "the same"),
            Map.entry("Connection.setCatalog(String)", "a database other than the one the "
                    + "connection is on cannot be had; the vendor ignores it silently"),
            Map.entry("Connection.setSchema(String)", "SQL Server: a schema other than the "
                    + "user's default cannot be had; mssql-jdbc ignores it silently"),
            Map.entry("Connection.prepareStatement(String,int[])", "keys by column number: "
                    + "name the columns"),
            Map.entry("Connection.createStruct(String,Object[])", "no user-defined types"),
            Map.entry("ResultSet.getRef", "no REF type on any of the four"),
            Map.entry("PreparedStatement.setRef", "no REF type on any of the four"),
            Map.entry("CallableStatement.setRef", "no REF type on any of the four"),
            Map.entry("CallableStatement.getRef", "no REF type on any of the four"),
            Map.entry("CallableStatement.setUnicodeStream", "deprecated since JDBC 2"),
            Map.entry("CallableStatement.addBatch()", "a batch of calls would need one set of "
                    + "OUT values per call; run the call in a loop"),
            Map.entry("CallableStatement.getArray", "arrays are read from result columns, not "
                    + "from OUT parameters"),
            Map.entry("Connection.setHoldability(int)", "results end with the transaction: a "
                    + "result read in blocks lives in a cursor or portal the commit closes"),
            Map.entry("Connection.createArrayOf", "SQL Server has no ARRAY type; on PostgreSQL "
                    + "only the element type names it knows"),
            Map.entry("ResultSet.getArray", "SQL Server has no ARRAY type; Oracle's are "
                    + "user-defined collection types"),
            Map.entry("ResultSet.getRowId", "SQL Server has no ROWID type"),
            Map.entry("Connection.prepareStatement(String,int)", "Oracle: RETURN_GENERATED_KEYS "
                    + "hands back a ROWID through ojdbc, not the key; name the key columns"),
            Map.entry("Statement.execute(String,", "Oracle: keys need a prepared statement "
                    + "with the columns named"),
            Map.entry("Statement.executeUpdate(String,", "the same"),
            Map.entry("Statement.executeLargeUpdate(String,", "the same")));

    private record Target(String name, String ours, String vendor, String user, Path secret,
                          String query, String call) {
    }

    @Test
    void postgresql() throws Exception {
        Path secret = TypeCatalogTest.locate(TestHosts.postgresPasswordFile());
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        TypeCatalogTest.reachable(host, port, secret);
        compare(new Target("PostgreSQL",
                "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test?user=seclume_test"
                        + "&tls=off",
                "jdbc:postgresql://" + host + ":" + port + "/seclume_test", "seclume_test", secret,
                "select 1 as a, 'x' as b", "{? = call abs(?)}"));
    }

    @Test
    void mysql() throws Exception {
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path secret = TypeCatalogTest.locate(".local-mysql-password");
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        compare(new Target("MySQL",
                "jdbc:seclume:mysql://" + host + ":" + port + "/seclume_test?user=seclume_test"
                        + "&tls=off&allowPublicKeyRetrieval=true",
                "jdbc:mysql://" + host + ":" + port
                        + "/seclume_test?allowPublicKeyRetrieval=true&sslMode=DISABLED",
                "seclume_test", secret, "select 1 as a, 'x' as b", "{? = call abs(?)}"));
    }

    @Test
    void sqlServer() throws Exception {
        int port = Integer.getInteger("seclume.mssql.port", 1433);
        Path secret = TypeCatalogTest.locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        compare(new Target("SQL Server",
                "jdbc:seclume:sqlserver://" + host + ":" + port
                        + "/master?user=sa&trustServerCertificate=true",
                "jdbc:sqlserver://" + host + ":" + port
                        + ";databaseName=master;encrypt=true;trustServerCertificate=true",
                "sa", secret, "select 1 as a, 'x' as b", "{call sp_who(?)}"));
    }

    @Test
    void oracle() throws Exception {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path secret = TypeCatalogTest.locate(".local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        compare(new Target("Oracle",
                "jdbc:seclume:oracle://" + host + ":" + port + "/FREEPDB1?user=seclume_test",
                "jdbc:oracle:thin:@//" + host + ":" + port + "/FREEPDB1", "seclume_test", secret,
                "select 1 as a, 'x' as b from dual", "{? = call abs(?)}"));
    }

    /** Makes a fresh object of one interface on a connection. */
    private interface Maker {
        Object make(Connection connection, Target target) throws Exception;
    }

    private static final Map<Class<?>, Maker> MAKERS = Map.of(
            Connection.class, (c, t) -> c,
            Statement.class, (c, t) -> c.createStatement(),
            PreparedStatement.class, (c, t) -> c.prepareStatement(t.query()),
            CallableStatement.class, (c, t) -> c.prepareCall(t.call()),
            ResultSet.class, (c, t) -> {
                ResultSet rows = c.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY).executeQuery(t.query());
                rows.next();
                return rows;
            },
            ResultSetMetaData.class, (c, t) ->
                    c.createStatement().executeQuery(t.query()).getMetaData());

    private static void compare(Target target) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", target.user());
        vendor.setProperty("password", Files.readString(target.secret()).trim());
        String ours = target.ours() + "&provider=file&path=" + TypeCatalogTest.slash(target.secret());
        Set<String> gaps = new TreeSet<>();
        Set<String> decided = new TreeSet<>();
        Set<String> beyond = new TreeSet<>();
        // Every method on a fresh connection of each driver - a method may change
        // the connection's state - so this is two logins per method, thousands in
        // all. They go out eight at a time: one after the other it was the
        // slowest class of the build (76 s, Oracle alone 43). Oracle not: its
        // listener turns a burst of logins away (ORA-12516) - these and, with
        // the modules building side by side, other modules' logins too. One at
        // a time is the rate it has always taken.
        record Verdict(String name, boolean mine, boolean theirs) {
        }
        List<java.util.concurrent.Future<Verdict>> verdicts = new ArrayList<>();
        java.util.concurrent.ExecutorService logins =
                java.util.concurrent.Executors.newFixedThreadPool(
                        target.name().equals("Oracle") ? 1 : 8);
        try {
            for (Map.Entry<Class<?>, Maker> kind : MAKERS.entrySet()) {
                List<Method> all = new ArrayList<>(Arrays.asList(kind.getKey().getMethods()));
                all.sort(Comparator.comparing(ApiSurfaceTest::signature));
                for (Method method : all) {
                    if (Modifier.isStatic(method.getModifiers()) || skipped(method)) {
                        continue;
                    }
                    String name = kind.getKey().getSimpleName() + "." + signature(method);
                    verdicts.add(logins.submit(() -> new Verdict(name,
                            refused(ours, null, kind.getValue(), method, target),
                            refused(target.vendor(), vendor, kind.getValue(), method, target))));
                }
            }
            for (java.util.concurrent.Future<Verdict> future : verdicts) {
                Verdict verdict;
                try {
                    verdict = future.get();
                } catch (java.util.concurrent.ExecutionException e) {
                    throw e.getCause() instanceof Exception cause ? cause : e;
                }
                if (verdict.mine() && !verdict.theirs()) {
                    String reason = reason(verdict.name());
                    if (reason != null) {
                        decided.add(verdict.name() + " - " + reason);
                    } else {
                        gaps.add(verdict.name());
                    }
                } else if (!verdict.mine() && verdict.theirs()) {
                    beyond.add(verdict.name());
                }
            }
        } finally {
            logins.shutdownNow();
        }
        int methods = verdicts.size();
        StringBuilder report = new StringBuilder("\n==== " + target.name() + ": " + methods
                + " methods\n");
        report.append("  refused by seclume, done by the vendor (").append(gaps.size())
                .append("):\n");
        gaps.forEach(g -> report.append("    ").append(g).append('\n'));
        report.append("  refused on purpose (").append(decided.size()).append(")\n");
        report.append("  done by seclume, refused by the vendor (").append(beyond.size())
                .append("): ").append(beyond).append('\n');
        System.out.println(report);
        assertTrue(gaps.isEmpty(), target.name() + ": " + gaps.size()
                + " methods the vendor has and seclume refuses:\n" + String.join("\n", gaps));
    }

    private static String reason(String name) {
        for (Map.Entry<String, String> decided : DECIDED.entrySet()) {
            String key = decided.getKey();
            if (key.endsWith("*") ? name.startsWith(key.substring(0, key.length() - 1))
                    : key.endsWith(")") ? name.equals(key) : name.startsWith(key)) {
                return decided.getValue();
            }
        }
        return null;
    }

    /** Methods that end the object or the test rather than show whether they exist. */
    private static boolean skipped(Method method) {
        return switch (method.getName()) {
            case "close", "abort", "unwrap", "isWrapperFor", "wait", "notify", "notifyAll",
                 "hashCode", "equals", "toString", "getClass", "cancel", "beginRequest",
                 "endRequest", "setShardingKey", "setShardingKeyIfValid" -> true;
            default -> false;
        };
    }

    private static String signature(Method method) {
        StringBuilder text = new StringBuilder(method.getName()).append('(');
        Class<?>[] types = method.getParameterTypes();
        for (int i = 0; i < types.length; i++) {
            text.append(i > 0 ? "," : "").append(types[i].getSimpleName());
        }
        return text.append(')').toString();
    }

    /** Whether the method answers "not supported" on a fresh object. */
    private static boolean refused(String url, Properties vendor, Maker maker, Method method,
                                   Target target) throws Exception {
        try (Connection connection = login(url, vendor)) {
            Object object = maker.make(connection, target);
            try {
                method.invoke(object, arguments(method, target));
                return false;
            } catch (InvocationTargetException thrown) {
                return thrown.getCause() instanceof SQLFeatureNotSupportedException;
            } catch (IllegalArgumentException wrongArguments) {
                return false;
            }
        }
    }

    /**
     * A login - again, when Oracle's listener turned it away for the moment.
     *
     * <p>Under a stream of short logins the listener's count of free server
     * processes runs behind the processes that already ended, and it refuses
     * with ORA-12516 / 12519 / 12520 although there is room. Nothing about
     * the method under test; the next attempt a moment later gets in.
     */
    private static Connection login(String url, Properties vendor) throws Exception {
        for (int attempt = 1; ; attempt++) {
            try {
                return vendor == null ? DriverManager.getConnection(url)
                        : DriverManager.getConnection(url, vendor);
            } catch (SQLException e) {
                boolean busy = e.getErrorCode() == 12516 || e.getErrorCode() == 12519
                        || e.getErrorCode() == 12520;
                if (!busy || attempt >= 50) {
                    throw e;
                }
                Thread.sleep(100);
            }
        }
    }

    private static Object[] arguments(Method method, Target target) {
        Class<?>[] types = method.getParameterTypes();
        Object[] values = new Object[types.length];
        for (int i = 0; i < types.length; i++) {
            values[i] = value(types[i], method, target);
        }
        return values;
    }

    private static Object value(Class<?> type, Method method, Target target) {
        if (type == int.class) {
            return 1;
        }
        if (type == long.class) {
            return 1L;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == short.class) {
            return (short) 1;
        }
        if (type == byte.class) {
            return (byte) 1;
        }
        if (type == double.class) {
            return 1.0;
        }
        if (type == float.class) {
            return 1.0f;
        }
        if (type == String.class) {
            String owner = method.getDeclaringClass().getSimpleName();
            return owner.equals("ResultSet") || owner.equals("CallableStatement") ? "a"
                    : owner.equals("Connection") && method.getName().startsWith("prepare")
                    ? target.query() : owner.equals("Statement")
                    && method.getName().startsWith("execute") ? target.query() : "a";
        }
        if (type == int[].class) {
            return new int[] {1};
        }
        if (type == String[].class) {
            return new String[] {"a"};
        }
        if (type == byte[].class) {
            return new byte[] {1};
        }
        if (type == Object[].class) {
            return new Object[] {1};
        }
        if (type == java.util.concurrent.Executor.class) {
            return (java.util.concurrent.Executor) Runnable::run;
        }
        if (type == Class.class) {
            return String.class;
        }
        if (type == java.util.Map.class) {
            return new java.util.HashMap<>();
        }
        if (type == java.util.Properties.class) {
            return new Properties();
        }
        if (type == java.math.BigDecimal.class) {
            return java.math.BigDecimal.ONE;
        }
        if (type == java.io.InputStream.class) {
            return new java.io.ByteArrayInputStream(new byte[] {1});
        }
        if (type == java.io.Reader.class) {
            return new java.io.StringReader("a");
        }
        if (type == java.sql.Date.class) {
            return java.sql.Date.valueOf("2026-09-25");
        }
        if (type == java.sql.Time.class) {
            return java.sql.Time.valueOf("12:00:00");
        }
        if (type == java.sql.Timestamp.class) {
            return java.sql.Timestamp.valueOf("2026-09-25 12:00:00");
        }
        if (type == java.util.Calendar.class) {
            return java.util.Calendar.getInstance();
        }
        if (type == java.sql.SQLType.class) {
            return java.sql.JDBCType.INTEGER;
        }
        if (type == Object.class) {
            return 1;
        }
        return null;
    }
}
