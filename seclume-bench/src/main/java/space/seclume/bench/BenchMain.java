package space.seclume.bench;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.openjdk.jmh.Main;

/**
 * The entry point of the measuring rig.
 *
 * <p>Without arguments it first <b>checks</b> that both sides really reach the
 * database and only then starts JMH. A benchmark that fails in its setup after
 * ten minutes of warmup is a wasted evening, and the check costs a second.
 *
 * <pre>
 * java -jar seclume-bench.jar -Dbench.db=postgresql ...        # everything
 * java -jar seclume-bench.jar QueryBenchmark                   # one class
 * java -jar seclume-bench.jar RecordBenchmark                  # no database at all
 * java -jar seclume-bench.jar -l                               # list them
 * </pre>
 */
public final class BenchMain {

    private BenchMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || !args[0].startsWith("-") && !onlyWithoutDatabase(args)) {
            check();
        }
        Main.main(withBenchProperties(args));
    }

    /** Benchmarks that measure seclume's own code and need no server. */
    private static final java.util.Set<String> WITHOUT_DATABASE =
            java.util.Set.of("RecordBenchmark");

    /** Whether every benchmark named before the first option is one of those. */
    private static boolean onlyWithoutDatabase(String[] args) {
        boolean any = false;
        for (String arg : args) {
            if (arg.startsWith("-")) {
                break;
            }
            int dot = arg.indexOf('.');
            if (!WITHOUT_DATABASE.contains(dot < 0 ? arg : arg.substring(0, dot))) {
                return false;
            }
            any = true;
        }
        return any;
    }

    /**
     * Passes the {@code bench.*} settings on to the forked JVMs.
     *
     * <p>JMH measures in a JVM of its own, and that one does <b>not</b> inherit
     * the system properties of the launcher. Without this, every measurement
     * silently runs against the defaults - which cost an hour here: a run
     * started with {@code -Dbench.db=mysql} printed MySQL in the check, which
     * happens in this JVM, and then measured PostgreSQL in the forked one. The
     * numbers looked plausible, and that is what made it expensive.
     */
    private static String[] withBenchProperties(String[] args) {
        StringBuilder forwarded = new StringBuilder();
        for (String name : System.getProperties().stringPropertyNames()) {
            if (name.startsWith("bench.")) {
                if (!forwarded.isEmpty()) {
                    forwarded.append(' ');
                }
                forwarded.append("-D").append(name).append('=')
                        .append(System.getProperty(name));
            }
        }
        if (forwarded.isEmpty()) {
            return args;
        }
        String[] extended = new String[args.length + 2];
        System.arraycopy(args, 0, extended, 0, args.length);
        extended[args.length] = "-jvmArgsAppend";
        extended[args.length + 1] = forwarded.toString();
        return extended;
    }

    /** Opens both connections once and says what each side answers. */
    private static void check() throws SQLException {
        BenchDatabase database = BenchDatabase.fromSystemProperties();
        System.out.println("bench against " + database);
        report("seclume", database, database.seclume().getConnection());
        report("vendor  ", database,
                DriverManager.getConnection(database.vendorUrl(), database.vendorProperties()));
    }

    private static void report(String label, BenchDatabase database, Connection connection)
            throws SQLException {
        try (Connection open = connection;
             Statement statement = open.createStatement();
             ResultSet result = statement.executeQuery(database.selectOne())) {
            result.next();
            System.out.println("  " + label + " -> " + open.getMetaData().getDriverName()
                    + " " + open.getMetaData().getDriverVersion()
                    + ", select 1 = " + result.getInt(1));
        }
    }
}
