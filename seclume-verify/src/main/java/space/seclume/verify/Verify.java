package space.seclume.verify;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import space.seclume.Pipelined;
import space.seclume.RoundTrips;
import space.seclume.Secured;

/**
 * One connection, one report.
 *
 * <p>Run before anything else in a strange environment:
 *
 * <pre>{@code java -jar seclume-verify.jar "jdbc:seclume:postgresql://db:5432/app?user=app&provider=file&path=/run/secrets/db"}</pre>
 *
 * <p>With {@code --json} in front of the URL the same report comes out as one
 * JSON object and nothing else - for a build step, or for a readiness probe
 * that wants a field rather than a paragraph. The exit code does not change,
 * because the exit code is the contract: <b>0</b> the connection stands,
 * <b>1</b> it does not, <b>2</b> the tool was called wrongly.
 *
 * <p>What comes out is meant to be pasted into a ticket: which driver took the
 * URL, which server answered and in what version, where the secret comes from,
 * what this driver can do <b>against this server</b>, and how many round trips
 * the everyday shapes cost. No driver knows any of that without trying, which
 * is why three days are usually spent guessing instead.
 *
 * <p><b>It changes nothing.</b> Every statement it runs is a read; there is no
 * table, no write, no setting left behind. A preflight check that alters the
 * database it is checking would be a strange kind of check.
 *
 * <p><b>And it never prints a secret.</b> It reports where the password comes
 * from - the provider and, say, the path - and not one byte of the password
 * itself. That is the whole point of the library it belongs to.
 */
public final class Verify {

    private Verify() {
    }

    public static void main(String[] arguments) {
        if (arguments.length == 2 && arguments[0].strip().equals("--migrate")) {
            System.exit(Migrate.run(arguments[1].strip(), System.out, System.err));
            return;
        }
        boolean json = false;
        boolean printPin = false;
        String url = null;
        for (String argument : arguments) {
            String value = argument.strip();
            if (value.equals("--json")) {
                json = true;
            } else if (value.equals("--print-pin")) {
                printPin = true;
            } else if (url == null && !value.isBlank()) {
                url = value;
            } else {
                url = null;
                break;
            }
        }
        if (url == null) {
            System.err.println("""
                    usage: java -jar seclume-verify.jar [--json] "<jdbc url>"
                           java -jar seclume-verify.jar --print-pin "<jdbc url>"
                           java -jar seclume-verify.jar --migrate <application.properties | jdbc url>

                    The URL is the one the application uses, password included -
                    which is to say: not included. It names where the secret comes
                    from, for example provider=file&path=/run/secrets/db.

                    --json prints the same report as one JSON object on stdout and
                    nothing else, for a pipeline or a readiness probe. The exit code
                    is the same either way: 0 it stands, 1 it does not, 2 this was
                    called wrongly.

                    --print-pin connects once without checking the certificate, and
                    prints the pin of the key the server presented - tlsPin=sha256/...
                    for the URL - with the certificate's subject, issuer and expiry,
                    to compare with what the server's owner says it should be.

                    --migrate translates a pgjdbc, Connector/J, MariaDB, mssql-jdbc,
                    Oracle thin or HikariCP configuration into seclume's, and names
                    every unsafe setting in it. Password values are never read.
                    Exit code 1 means unsafe settings were found.""");
            System.exit(2);
            return;
        }
        if (printPin) {
            System.exit(printPin(url));
            return;
        }
        Report report = new Report();
        int status = run(url, report);
        System.out.print(json ? report.json(status) : report.toString());
        System.exit(status);
    }

    /**
     * The pin of the server's key, from one connection that checks nothing -
     * which is why what it prints has to be compared with what the server's
     * owner says, before it is trusted.
     */
    static int printPin(String url) {
        String unchecked = uncheckedTls(url);
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(unchecked)) {
            java.security.cert.X509Certificate presented =
                    Secured.of(connection).serverCertificate();
            if (presented == null) {
                System.err.println("the server did not use TLS on this connection - there is "
                        + "no certificate to pin");
                return 1;
            }
            System.out.println("tlsPin=" + space.seclume.internal.TrustChoice.pinOf(presented));
            System.out.println("  subject  " + presented.getSubjectX500Principal().getName());
            System.out.println("  issuer   " + presented.getIssuerX500Principal().getName());
            System.out.println("  expires  " + presented.getNotAfter().toInstant());
            System.out.println("Unchecked: compare the pin with the server's owner before "
                    + "putting it into the URL.");
            return 0;
        } catch (java.sql.SQLException e) {
            System.err.println("could not connect: " + e.getMessage());
            return 1;
        }
    }

    /** The URL with its own trust settings replaced by encryption without checking. */
    static String uncheckedTls(String url) {
        int question = url.indexOf('?');
        int hash = url.indexOf('#');
        String tail = hash < 0 ? "" : url.substring(hash);
        String base = question < 0 ? (hash < 0 ? url : url.substring(0, hash))
                : url.substring(0, question);
        StringBuilder kept = new StringBuilder();
        if (question >= 0) {
            String query = hash < 0 ? url.substring(question + 1)
                    : url.substring(question + 1, hash);
            for (String option : query.split("&")) {
                String key = option.contains("=") ? option.substring(0, option.indexOf('='))
                        : option;
                if (key.equalsIgnoreCase("tls") || key.equalsIgnoreCase("tlsPin")
                        || key.equalsIgnoreCase("tlsRootCert") || option.isBlank()) {
                    continue;
                }
                kept.append(kept.isEmpty() ? "" : "&").append(option);
            }
        }
        return base + "?" + kept + (kept.isEmpty() ? "" : "&") + "tls=require" + tail;
    }

    /** Everything the report needs; separate so a test can read it back. */
    static int run(String url, Report report) {
        report.title("seclume-verify");
        report.line("url", withoutSecrets(url));
        Driver driver;
        try {
            driver = DriverManager.getDriver(url);
        } catch (SQLException e) {
            report.line("driver", "none - no seclume driver accepts this URL");
            report.problem("Add the driver dependency for this database, or check the "
                    + "prefix: it has to be jdbc:seclume:postgresql, :mysql, :sqlserver "
                    + "or :oracle.");
            return 1;
        }
        report.line("driver", driver.getClass().getName()
                + " " + driver.getMajorVersion() + "." + driver.getMinorVersion());
        report.line("secret", secretSource(url));

        long started = System.nanoTime();
        try (Connection connection = DriverManager.getConnection(url)) {
            report.line("connect", millis(System.nanoTime() - started) + " ms");
            server(connection, report);
            capacity(connection, report);
            capabilities(connection, url, report);
            roundTrips(connection, report);
            report.title("verdict");
            report.line("result", report.hasProblems()
                    ? "reachable, with the notes above" : "everything answers");
            return 0;
        } catch (SQLException e) {
            report.title("connect");
            report.line("failed", "after " + millis(System.nanoTime() - started) + " ms");
            report.line("state", String.valueOf(e.getSQLState()));
            report.line("said", oneLine(e.getMessage()));
            // The driver's own sentence is the summary; what actually went
            // wrong is usually a line further down. A refused certificate
            // arrives as "the login failed" with an SSLHandshakeException
            // underneath, and without this line nobody would know to trust the
            // server or fix its certificate.
            String cause = rootCause(e);
            if (cause != null) {
                report.line("because", cause);
            }
            for (Throwable other : e.getSuppressed()) {
                report.line("also", oneLine(other.getMessage()));
            }
            report.problem(advice(e));
            return 1;
        }
    }

    /** How many connections the server allows and has - see ServerCapacity. */
    private static void capacity(Connection connection, Report report) {
        try {
            space.seclume.ServerCapacity.Capacity capacity =
                    connection.unwrap(space.seclume.ServerCapacity.class).capacity();
            report.line("capacity", capacity.known()
                    ? capacity.allowed() + " connections allowed, " + capacity.inUse()
                            + " in use, " + capacity.free() + " free"
                    : "not visible to this user"
                            + (capacity.allowed() >= 0 ? " (" + capacity.allowed()
                                    + " allowed)" : ""));
        } catch (SQLException | RuntimeException e) {
            report.line("capacity", "not asked: " + e.getMessage());
        }
    }

    private static void server(Connection connection, Report report) throws SQLException {
        DatabaseMetaData meta = connection.getMetaData();
        report.title("server");
        report.line("product", meta.getDatabaseProductName() + " "
                + meta.getDatabaseProductVersion());
        report.line("user", orDash(meta.getUserName()));
        // Oracle has no catalogs at all; a dash says that better than "null".
        report.line("catalog", orDash(connection.getCatalog()));
        report.line("read only", String.valueOf(connection.isReadOnly()));
        report.line("isolation", isolationName(connection.getTransactionIsolation()));
    }

    private static void capabilities(Connection connection, String url, Report report)
            throws SQLException {
        report.title("what this driver can do against this server");
        report.line("round trips counted", String.valueOf(RoundTrips.of(connection) >= 0));
        security(report, connection);

        Pipelined pipelined = Pipelined.of(connection);
        String bundles = "no - this driver does not offer the block";
        if (pipelined != null) {
            boolean auto = connection.getAutoCommit();
            try {
                connection.setAutoCommit(false);
                pipelined.beginPipeline();
                bundles = pipelined.isPipelining()
                        ? "yes - writes in a Pipeline block go out together"
                        : "accepted, but saves nothing on this database";
                pipelined.endPipeline();
            } finally {
                connection.rollback();
                connection.setAutoCommit(auto);
            }
        }
        report.line("pipeline block", bundles);
        report.line("block cursors", blockCursors(connection));
        report.line("generated keys", generatedKeys(connection));
        report.line("two-phase commit", twoPhase(connection));
        report.line("result limit", limitOf(url));
        report.line("failover", hostsOf(url));
    }

    /**
     * Whether a fetch size really reads in blocks on this server.
     *
     * <p>Asked by doing it: a small fetch size over a result of a few rows
     * costs more than one round trip when the rows come in blocks, and exactly
     * one when they do not. No driver knows this about a server without
     * trying, which is the whole reason this command exists.
     */
    private static String blockCursors(Connection connection) {
        String probe = null;
        try {
            probe = blockProbe(connection);
            if (probe == null) {
                return "not probed on this database";
            }
            boolean auto = connection.getAutoCommit();
            try {
                connection.setAutoCommit(false);     // PostgreSQL needs a transaction
                try (PreparedStatement query = connection.prepareStatement(probe)) {
                    query.setFetchSize(BLOCK_FETCH);
                    long before = RoundTrips.of(connection);
                    int seen = 0;
                    try (ResultSet rows = query.executeQuery()) {
                        while (rows.next()) {
                            seen++;
                        }
                    }
                    long spent = RoundTrips.of(connection) - before;
                    return spent > 1
                            ? "yes - " + seen + " rows came in " + spent + " round trips"
                            : "no - the whole result came at once";
                }
            } finally {
                connection.rollback();
                connection.setAutoCommit(auto);
            }
        } catch (SQLException e) {
            return "could not tell: " + oneLine(e.getMessage());
        }
    }

    /**
     * How many rows the probe asks for at a time, and over how many rows.
     *
     * <p>Both numbers are chosen to clear Oracle's prefetch. Its first block
     * brings a hundred rows whatever the fetch size says - the fetch size
     * governs the blocks <b>after</b> the first - so a probe over ten rows
     * reported "the whole result came at once" for a driver that reads in
     * blocks perfectly well. The probe was measuring its own size.
     */
    private static final int BLOCK_ROWS = 500;
    private static final int BLOCK_FETCH = 50;

    /** Enough rows without a table, spelled for this server. */
    private static String blockProbe(Connection connection) throws SQLException {
        String product = product(connection);
        if (product.contains("postgresql")) {
            return "select n from generate_series(1, " + BLOCK_ROWS + ") as n";
        }
        if (product.contains("oracle")) {
            return "select level from dual connect by level <= " + BLOCK_ROWS;
        }
        if (product.contains("mysql") || product.contains("mariadb")) {
            // A recursive CTE, which MySQL has had since 8.0 and MariaDB
            // since 10.2. The older note here said these two needed a table;
            // that stopped being true years ago, and the consequence was a
            // compatibility table saying "not probed" for half its columns.
            return "with recursive n(x) as (select 1 union all "
                    + "select x + 1 from n where x < " + BLOCK_ROWS + ") select x from n";
        }
        if (product.contains("sql server")) {
            // The same, spelled without the keyword: T-SQL says `with`.
            return "with n(x) as (select 1 union all "
                    + "select x + 1 from n where x < " + BLOCK_ROWS
                    + ") select x from n option (maxrecursion 0)";
        }
        return null;
    }

    /** Whether this driver can hand back the keys an insert generated. */
    private static String generatedKeys(Connection connection) {
        String product = product(connection);
        if (product.contains("oracle")) {
            return "yes, with named columns - Oracle needs a returning clause";
        }
        try {
            connection.getMetaData().supportsGetGeneratedKeys();
            return "yes";
        } catch (SQLException e) {
            return "could not tell: " + oneLine(e.getMessage());
        }
    }

    /** Whether the server would take a two-phase commit at all. */
    private static String twoPhase(Connection connection) {
        String product = product(connection);
        if (!product.contains("postgresql")) {
            return "XADataSource available - see the XA notes";
        }
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("show max_prepared_transactions")) {
            rows.next();
            int allowed = rows.getInt(1);
            return allowed > 0
                    ? "yes - max_prepared_transactions is " + allowed
                    : "off on this server - max_prepared_transactions is 0";
        } catch (SQLException e) {
            return "could not tell: " + oneLine(e.getMessage());
        }
    }

    private static String product(Connection connection) {
        try {
            String name = connection.getMetaData().getDatabaseProductName();
            return name == null ? "" : name.toLowerCase(java.util.Locale.ROOT);
        } catch (SQLException e) {
            return "";
        }
    }

    /**
     * The everyday shapes, counted rather than timed.
     *
     * <p>A number that does not depend on the network: it says what the driver
     * costs, and multiplied by the latency of this line it says what the
     * application will feel.
     */
    private static void roundTrips(Connection connection, Report report) throws SQLException {
        report.title("round trips");
        String probe = probeQuery(connection);
        boolean auto = connection.getAutoCommit();
        try {
            connection.setAutoCommit(false);
            long before = RoundTrips.of(connection);
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(probe)) {
                rows.next();
            }
            connection.commit();
            report.line("transaction, one query", String.valueOf(
                    RoundTrips.of(connection) - before));

            connection.setAutoCommit(true);
            // One throwaway statement before the measurement, and it is not
            // ceremony: setAutoCommit does not talk to the server, it queues a
            // setting to ride along with whatever comes next. Measured without
            // this, the count includes that setting and reads one too high -
            // which is exactly what the first version of this line did, and it
            // took a second instrument to notice.
            try (Statement flush = connection.createStatement();
                 ResultSet rows = flush.executeQuery(probe)) {
                rows.next();
            }

            // The first use of a prepared statement, measured from the
            // prepareStatement call rather than from the execution.
            //
            // This is the line that pays for itself. On PostgreSQL it stood at
            // three where one is enough, and neither the mean nor a percentile
            // showed it - one operation in a thousand is invisible in an
            // average and looks like noise in a tail. A count does not average.
            //
            // The text is made unique on purpose. Two of the four drivers keep
            // prepared statements per session, so asking for the same SQL twice
            // would measure a cache hit and report the first use as free.
            String fresh = probe + " /* seclume-verify */";
            long beforeFirst = RoundTrips.of(connection);
            try (PreparedStatement statement = connection.prepareStatement(fresh);
                 ResultSet rows = statement.executeQuery()) {
                rows.next();
            }
            report.line("prepared, first run", String.valueOf(
                    RoundTrips.of(connection) - beforeFirst));

            try (PreparedStatement prepared = connection.prepareStatement(probe)) {
                try (ResultSet warmup = prepared.executeQuery()) {
                    warmup.next();
                }
                long beforeSecond = RoundTrips.of(connection);
                try (ResultSet rows = prepared.executeQuery()) {
                    rows.next();
                }
                report.line("prepared, second run", String.valueOf(
                        RoundTrips.of(connection) - beforeSecond));
            }
        } finally {
            connection.setAutoCommit(auto);
        }
        report.line("measured with", probe);
    }

    /** {@code select 1}, and what the one database that insists on a table wants. */
    private static String probeQuery(Connection connection) throws SQLException {
        String product = connection.getMetaData().getDatabaseProductName();
        return product != null && product.toLowerCase(java.util.Locale.ROOT).contains("oracle")
                ? "select 1 from dual" : "select 1";
    }

    /** Where the password comes from - never what it is. */
    private static String secretSource(String url) {
        String provider = option(url, "provider");
        if (provider == null) {
            return "none named in the URL - the DataSource has to carry a SecretProvider";
        }
        StringBuilder text = new StringBuilder(provider); // seclume-allow: the source, not the secret
        String path = option(url, "path");
        if (path != null) {
            text.append(", path=").append(path);
        }
        String name = option(url, "name");
        if (name != null) {
            text.append(", name=").append(name);
        }
        text.append("  (not read here)");
        return text.toString();
    }

    private static String limitOf(String url) {
        String bytes = option(url, "maxResultBytes");
        String rows = option(url, "maxResultRows");
        if (bytes == null && rows == null) {
            return "off - a runaway query ends in an OutOfMemoryError";
        }
        return (bytes == null ? "" : bytes + " bytes ")
                + (rows == null ? "" : rows + " rows");
    }

    private static String hostsOf(String url) {
        int start = url.indexOf("//");
        int end = url.indexOf('/', start + 2);
        String authority = start < 0 ? "" : url.substring(start + 2, end < 0 ? url.length() : end);
        int servers = authority.isEmpty() ? 0 : authority.split(",").length;
        return servers > 1
                ? servers + " servers - the next one is used when one cannot be reached"
                : "one server - no failover";
    }

    /** The URL as it may appear in a ticket: values of secret options removed. */
    static String withoutSecrets(String url) {
        int question = url.indexOf('?');
        if (question < 0) {
            return url;
        }
        StringBuilder text = new StringBuilder(url.substring(0, question + 1)); // seclume-allow: a URL, and the secret is taken out of it here
        String[] options = url.substring(question + 1).split("&");
        for (int i = 0; i < options.length; i++) {
            if (i > 0) {
                text.append('&');
            }
            int equals = options[i].indexOf('=');
            String key = equals < 0 ? options[i] : options[i].substring(0, equals);
            // A password has no business being in a URL at all, and if somebody
            // put one there anyway it does not go into a report.
            if (key.equalsIgnoreCase("password") || key.equalsIgnoreCase("secret")) {
                text.append(key).append("=***");
            } else {
                text.append(options[i]);
            }
        }
        return text.toString();
    }

    private static String option(String url, String key) {
        int question = url.indexOf('?');
        if (question < 0) {
            return null;
        }
        for (String option : url.substring(question + 1).split("&")) {
            int equals = option.indexOf('=');
            if (equals > 0 && option.substring(0, equals).equalsIgnoreCase(key)) {
                return option.substring(equals + 1);
            }
        }
        return null;
    }

    /**
     * The deepest cause worth printing, or null when there is nothing below.
     *
     * <p>Named rather than the whole chain: a stack trace in a preflight report
     * is noise, and the bottom link is where the answer usually is.
     */
    private static String rootCause(Throwable failure) {
        Throwable cause = failure.getCause();
        if (cause == null) {
            return null;
        }
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        String message = cause.getMessage();
        String name = cause.getClass().getSimpleName();
        return message == null || message.isBlank() ? name : name + ": " + oneLine(message);
    }

    /** Whether a TLS failure is anywhere in the chain. */
    static boolean isTlsFailure(Throwable failure) {
        for (Throwable link = failure; link != null && link.getCause() != link;
                link = link.getCause()) {
            if (link instanceof javax.net.ssl.SSLException
                    || link instanceof java.security.cert.CertificateException) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the URL was refused before anything was dialled.
     *
     * <p>A setting the driver does not take - {@code password=} in the URL is
     * the common one - arrives as an {@code IllegalArgumentException} wrapped
     * in a connection failure, state {@code 08001}. Read by state alone that
     * is "the server was not reached", which is true and useless: no server
     * was ever asked.
     */
    static boolean isSettingFailure(Throwable failure) {
        for (Throwable link = failure; link != null && link.getCause() != link;
                link = link.getCause()) {
            if (link instanceof IllegalArgumentException) {
                return true;
            }
        }
        return false;
    }

    /** What to try next - the part a stack trace never tells anybody. */
    static String advice(SQLException failure) {
        String state = failure.getSQLState() == null ? "" : failure.getSQLState();
        // Before the state is read at all: a refused certificate is reported as
        // a connection failure - state 08 - and the advice for that one sends
        // the reader to check host, port and firewall, none of which is wrong.
        // The server was reached; it was the certificate that was not accepted.
        if (isTlsFailure(failure)) {
            return "The server was reached and TLS failed - see the cause above. Either the "
                    + "certificate is not signed by anything this JVM trusts (a container's "
                    + "own certificate never is), or the name in it does not match the host in "
                    + "the URL. Point the JVM at a truststore that has it, or say so "
                    + "deliberately in the URL: sslmode/trustServerCertificate, per driver.";
        }
        // Before anything about the network: the URL may never have been
        // dialled. Found by reading this tool's own output - a URL carrying
        // password= was answered with "check host, port and firewall", and
        // somebody would have checked all three.
        if (isSettingFailure(failure)) {
            return "The URL was refused before any server was asked - see the cause above. "
                    + "That is a setting in the URL, not the network: fix the option it "
                    + "names and run this again.";
        }
        if (state.startsWith("28")) {
            return "The server refused the login. The password comes from the source named "
                    + "above - check that source, not the URL.";
        }
        if (state.startsWith("08")) {
            return "The server was not reached at all. Check host, port and firewall; with "
                    + "several servers in the URL every one of them answered as shown above.";
        }
        if (state.startsWith("3D") || state.startsWith("42")) {
            return "The server answered but refused the database or the statement - the "
                    + "connection itself is fine.";
        }
        return "The server answered with the state above; that is what to look up.";
    }

    /**
     * Two lines no JDBC method can produce.
     *
     * <p>{@link java.sql.DatabaseMetaData} will say the server's version and
     * its keyword list, and has nothing whatever to say about how the password
     * travelled or whether anything was encrypting it. Those are the two facts
     * an operator wants before a migration and the two a table like this is
     * usually silent about - see {@link Secured}.
     *
     * <p><b>Not fatal when absent.</b> A driver that is not one of these four
     * cannot answer, and a report that refused to finish over it would be less
     * useful than one that says so in a cell.
     */
    private static void security(Report report, Connection connection) {
        try {
            Secured secured = Secured.of(connection);
            report.line("authentication", orDash(secured.authenticationMethod()));
            String tls = secured.tlsDescription();
            report.line("encryption", tls == null
                    ? "none - this connection is in the clear" : tls);
        } catch (SQLException notOurs) {
            report.line("authentication", "-");
            report.line("encryption", "-");
        }
    }

    private static String isolationName(int level) {
        return switch (level) {
            case Connection.TRANSACTION_READ_UNCOMMITTED -> "read uncommitted";
            case Connection.TRANSACTION_READ_COMMITTED -> "read committed";
            case Connection.TRANSACTION_REPEATABLE_READ -> "repeatable read";
            case Connection.TRANSACTION_SERIALIZABLE -> "serializable";
            case Connection.TRANSACTION_NONE -> "none";
            default -> "unknown (" + level + ")";
        };
    }

    private static long millis(long nanos) {
        return nanos / 1_000_000L;
    }

    private static String orDash(String text) {
        return text == null || text.isBlank() ? "-" : text;
    }

    private static String oneLine(String text) {
        return text == null ? "" : text.replace('\n', ' ').replace('\r', ' ');
    }
}
