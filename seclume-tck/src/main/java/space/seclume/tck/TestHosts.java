package space.seclume.tck;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;

/**
 * Where the databases the live tests need are reachable.
 *
 * <p>Nothing here decides anything; it only keeps the answer in one place
 * instead of in a hundred string literals. A checked-out copy of this project
 * says nothing about whose machine it was written on, and everybody points it
 * at their own servers the same way.
 *
 * <p>Three ways, in this order:
 *
 * <ol>
 *   <li>a system property on the command line -
 *       {@code mvn test -Dseclume.test.host=db.example.invalid},</li>
 *   <li>the environment variable {@code SECLUME_TEST_HOST} for the main
 *       host,</li>
 *   <li>a file {@code .local-test.properties} beside the project, or one
 *       level above it, holding any of the properties below. It is not
 *       checked in - like the password files next to it, it describes one
 *       machine and belongs to it.</li>
 * </ol>
 *
 * <pre>
 *   seclume.test.host=db.example.invalid   # MySQL, SQL Server, Oracle
 *   seclume.pg.host=db.example.invalid     # PostgreSQL, usually somewhere else
 *   seclume.pg.port=5433
 *   seclume.pg.passwordFile=.local-pgtls-password
 * </pre>
 *
 * <p>The defaults are {@code localhost} and {@code 127.0.0.1:5432}, which is
 * where a container started from {@code TESTING.md} listens. Tests that
 * find nothing there skip themselves rather than fail - see the
 * {@code Local...Test} classes.
 */
public final class TestHosts {

    /** The property that names the host, and the environment variable beside it. */
    public static final String PROPERTY = "seclume.test.host";
    public static final String ENVIRONMENT = "SECLUME_TEST_HOST";
    /** The file that answers all of it for one machine, if there is one. */
    public static final String FILE = ".local-test.properties";

    static {
        loadLocalFile();
    }

    private static final String RESOLVED = resolve();

    private TestHosts() {
    }

    /** The host the test databases run on. */
    public static String database() {
        return RESOLVED;
    }

    /**
     * PostgreSQL is the one that is usually not on that host.
     *
     * <p>Everybody has a PostgreSQL on their own machine, so the default is
     * the loopback address and the three properties below move it: the host,
     * the port, and which password file to read. That last one is what lets
     * the same tests run against a second instance - a TLS one, say - without
     * touching the one next to the editor.
     */
    public static String postgres() {
        return System.getProperty("seclume.pg.host", "127.0.0.1");
    }

    public static int postgresPort() {
        return Integer.getInteger("seclume.pg.port", 5432);
    }

    /** The name of the file the PostgreSQL password is in - never its content. */
    public static String postgresPasswordFile() {
        return System.getProperty("seclume.pg.passwordFile", ".local-pg-password");
    }

    /**
     * A server of the PostgreSQL family, named by a short key.
     *
     * <p>CockroachDB and YugabyteDB speak the same wire protocol, and the
     * point of testing against them is to find out whether "the same" holds
     * all the way down to the login. Each is described by four properties
     * under its own key - {@code seclume.crdb.*}, {@code seclume.yb.*} - so a
     * machine that has one and not the other simply says so and the tests for
     * the missing one skip themselves.
     *
     * <pre>
     *   seclume.crdb.host=db.example.invalid
     *   seclume.crdb.port=26257
     *   seclume.crdb.user=seclume_test       # the default
     *   seclume.crdb.database=seclume_test   # the default
     *   seclume.crdb.passwordFile=.local-crdb-password   # the default
     * </pre>
     */
    public record Server(String key, String host, int port, String user, String database,
                         String passwordFile) {
    }

    /**
     * What is configured for that key, with the defaults filled in.
     *
     * @param key          {@code crdb}, {@code yb}, or any other short name
     * @param defaultPort  the port that server usually listens on
     */
    public static Server server(String key, int defaultPort) {
        return new Server(key,
                System.getProperty("seclume." + key + ".host", database()),
                Integer.getInteger("seclume." + key + ".port", defaultPort),
                System.getProperty("seclume." + key + ".user", "seclume_test"),
                System.getProperty("seclume." + key + ".database", "seclume_test"),
                System.getProperty("seclume." + key + ".passwordFile",
                        ".local-" + key + "-password"));
    }

    /**
     * Whether that server was configured at all.
     *
     * <p>A host of its own is the signal. Without one the key falls back to
     * the main test host, which is almost certainly running something else.
     */
    public static boolean isConfigured(String key) {
        return System.getProperty("seclume." + key + ".host") != null;
    }

    /**
     * Reads the machine's own file, if it has one.
     *
     * <p>A value already given on the command line wins: the file is the
     * standing answer, the property is this run's.
     */
    private static void loadLocalFile() {
        // Two levels up as well: a nested module (seclume-quarkus/deployment).
        for (Path candidate : List.of(Path.of(FILE), Path.of("..", FILE),
                Path.of("..", "..", FILE))) {
            if (!Files.isReadable(candidate)) {
                continue;
            }
            Properties local = new Properties();
            try (InputStream in = Files.newInputStream(candidate)) {
                local.load(in); // seclume-allow: host names and file names, no secret is in this file
            } catch (IOException e) {
                return;
            }
            for (String name : local.stringPropertyNames()) {
                if (name.startsWith("seclume.") && System.getProperty(name) == null) {
                    System.setProperty(name, local.getProperty(name).trim());
                }
            }
            return;
        }
    }

    private static String resolve() {
        String named = System.getProperty(PROPERTY);
        if (named == null || named.isBlank()) {
            // seclume-allow: a host name, and the test harness is not the driver
            named = System.getenv(ENVIRONMENT);
        }
        return named == null || named.isBlank() ? "localhost" : named.trim();
    }
}
