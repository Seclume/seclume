package space.seclume.verify;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

import space.seclume.Secured;
import space.seclume.ServerCapacity;
import space.seclume.internal.JdbcUrl;
import space.seclume.internal.MemoryLock;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.SecretScope;

/** Read-only diagnostics. Never echo a URL, provider option or exception message. */
final class Doctor {
    private Doctor() { }

    static int mainRun(String[] args, PrintStream out, PrintStream err) {
        boolean json = false;
        String url = null;
        Integer poolSize = null;
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--doctor" -> { }
                    case "--json" -> json = true;
                    case "--pool-size" -> {
                        poolSize = Integer.valueOf(args[++i]);
                        if (poolSize <= 0) throw new IllegalArgumentException();
                    }
                    default -> {
                        if (url != null || args[i].startsWith("--")) throw new IllegalArgumentException();
                        url = args[i];
                    }
                }
            }
            if (url == null) throw new IllegalArgumentException();
        } catch (IllegalArgumentException | IndexOutOfBoundsException invalid) {
            err.println("usage: --doctor [--json] [--pool-size positive-integer] <seclume jdbc url>");
            return 2;
        }
        Report report = new Report();
        int status = run(url, poolSize, report);
        out.print(json ? report.json(status) : report.toString());
        return status;
    }

    static int run(String url, Integer poolSize, Report report) {
        report.title("doctor");
        JdbcUrl.Parsed settings;
        try {
            settings = settings(url);
        } catch (RuntimeException invalid) {
            report.problem("Use a seclume PostgreSQL, MySQL, SQL Server or Oracle network JDBC URL.");
            return 2;
        }
        if (settings.option("password") != null || settings.option("pwd") != null) {
            report.problem("Remove the inline password; configure provider=file and path, or another secret provider.");
            return 2;
        }
        memory(report);
        source(settings, report);
        try (Connection connection = DriverManager.getConnection(url)) {
            report.line("connection", "PASS - login succeeded using the configured source");
            inspect(connection, settings, poolSize, report);
        } catch (SQLException | RuntimeException failed) {
            report.line("connection", "FAIL - connection or diagnostics failed");
            // SQLState and messages can be supplied by third-party code or the server.
            // Neither belongs in a report promising not to disclose credentials.
            report.problem("Check reachability, the database user, provider access and certificate trust. "
                    + "For private CAs configure tlsRootCert; keep certificate validation enabled.");
            return 1;
        }
        report.line("scope", "This process and one connection at this instant; not a heap-leak proof "
                + "or validation of another JVM's pool. Use heapcheck under application load.");
        return report.hasProblems() ? 1 : 0;
    }

    static JdbcUrl.Parsed settings(String url) {
        for (String database : new String[] {"postgresql", "mysql", "sqlserver", "oracle"}) {
            String prefix = "jdbc:seclume:" + database + ":";
            if (url.startsWith(prefix + "//")) {
                int port = switch (database) {
                    case "postgresql" -> 5432;
                    case "mysql" -> 3306;
                    case "sqlserver" -> 1433;
                    default -> 1521;
                };
                return JdbcUrl.parse(url, new Properties(), prefix, port);
            }
        }
        throw new IllegalArgumentException();
    }

    private static void source(JdbcUrl.Parsed settings, Report report) {
        if ("file".equals(settings.option("provider"))) {
            String path = settings.option("path");
            try {
                if (path == null || !Files.isRegularFile(Path.of(path)) || !Files.isReadable(Path.of(path))) {
                    report.problem("The secret file is missing or unreadable. Check its mount and permissions.");
                    report.line("secret source", "FAIL - file unavailable");
                    return;
                }
                report.line("secret source", "PASS - secret file is readable; its contents were not inspected");
            } catch (RuntimeException invalid) {
                report.problem("Correct the secret file path and permissions.");
            }
        } else {
            report.line("secret source", "CHECK - provider or integrated authentication is tested by login");
        }
    }

    private static void memory(Report report) {
        try (SecretScope probe = SecretScope.allocate(4096)) {
            boolean locked = probe.isLocked();
            boolean excluded = MemoryLock.excludeFromDumps(probe.segment());
            report.line("memory lock", locked ? "PASS - probe page locked in this JVM" : "FAIL - probe page not locked");
            report.line("crash dumps", excluded ? "PASS - probe page excluded" : "FAIL - exclusion unavailable");
            if (!locked || !excluded) report.problem("Check native access, OS memlock limits and dump exclusion support. "
                    + "Use -Dseclume.mlock.required=true in the application to require both protections.");
        } catch (RuntimeException failed) {
            report.problem("Native memory protection failed. Check --enable-native-access=ALL-UNNAMED and OS limits.");
        }
    }

    static void inspect(Connection connection, JdbcUrl.Parsed settings, Integer poolSize,
                        Report report) throws SQLException {
        Secured secured = Secured.of(connection);
        String tls = secured.tlsDescription();
        boolean nativeTls = tls != null && tls.contains("(seclume)");
        report.line("TLS stack", tls == null ? "FAIL - no TLS" : nativeTls
                ? "PASS - seclume TLS negotiated" : "FAIL - TLS uses a stack without the native-memory guarantee");
        if (!nativeTls) report.problem("Use tlsStack=seclume with a TLS 1.3 capable server; "
                + "SQL Server also requires tds=8.0. A successful JSSE connection is not an off-heap TLS proof.");
        boolean verified = settings.option("trustServerCertificate") == null
                || !settings.flag("trustServerCertificate", false);
        // SQL Server validates by default. Other drivers follow TlsMode.
        boolean sqlServer = connection.getClass().getName().startsWith("space.seclume.sqlserver.");
        verified &= sqlServer || TlsMode.of(settings.option("tls")).verifies();
        // The common TLS layer checks a configured pin independently of TlsMode.
        // Older SQL Server's nested JSSE handshake has different trust handling.
        verified |= !sqlServer && settings.option("tlsPin") != null;
        if (tls == null || !verified) {
            report.line("certificate trust", "FAIL - verified TLS was not established by these settings");
            report.problem("Set tls=verify-full (SQL Server: trustServerCertificate=false); "
                    + "use tlsRootCert for a private CA or a separately verified tlsPin.");
        } else {
            report.line("certificate trust", "PASS - login completed with verification configured");
        }
        var certificate = secured.serverCertificate();
        if (certificate != null) {
            try {
                certificate.checkValidity();
                report.line("certificate validity", "PASS - within its validity period");
                if (certificate.getNotAfter().toInstant().isBefore(java.time.Instant.now().plusSeconds(30L * 86400))) {
                    report.problem("Renew the server certificate: it expires within 30 days.");
                }
            } catch (java.security.cert.CertificateException invalid) {
                report.problem("Replace the expired or not-yet-valid server certificate; check system time.");
            }
        } else {
            report.line("certificate validity", "UNKNOWN - driver did not expose a certificate");
        }
        if (poolSize == null) {
            report.line("pool capacity", "NOT CHECKED - pass --pool-size with the application's maximum pool size");
        } else {
            try {
                var capacity = connection.unwrap(ServerCapacity.class).capacity();
                report.line("pool capacity", capacity.known()
                        ? "requested " + poolSize + ", currently free " + capacity.free()
                        : "UNKNOWN - capacity not visible to this database user");
                if (capacity.known() && poolSize > capacity.free()) {
                    report.problem("Reduce maximum-pool-size or increase database capacity; "
                            + "reserve headroom for other application replicas and administration.");
                }
            } catch (SQLException | RuntimeException unavailable) {
                report.line("pool capacity", "UNKNOWN - server capacity could not be read");
            }
        }
    }
}
