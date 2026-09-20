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
     * Reads the machine's own file, if it has one.
     *
     * <p>A value already given on the command line wins: the file is the
     * standing answer, the property is this run's.
     */
    private static void loadLocalFile() {
        for (Path candidate : List.of(Path.of(FILE), Path.of("..", FILE))) {
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
