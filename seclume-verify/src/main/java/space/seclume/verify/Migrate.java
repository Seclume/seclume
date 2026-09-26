package space.seclume.verify;

import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * Translates an existing configuration - pgjdbc, MySQL Connector/J, MariaDB,
 * mssql-jdbc, Oracle thin, HikariCP, Spring's {@code spring.datasource.*} -
 * into seclume's, and says out loud which of its settings were unsafe.
 *
 * <pre>
 *   java -jar seclume-verify.jar --migrate application.properties
 *   java -jar seclume-verify.jar --migrate "jdbc:postgresql://db/app?sslmode=require"
 * </pre>
 *
 * <p>The lowest entry barrier there is: nobody has to learn the option names
 * of a new driver to try it, and the settings that were quietly wrong -
 * {@code trustServerCertificate=true}, {@code sslmode=prefer}, a password in
 * the file - are named on the way, which is worth knowing whether or not
 * seclume is ever used.
 *
 * <p><b>A password is never read.</b> A property that holds one is noted by
 * its name, and its value is dropped the moment the file is loaded; the
 * translation points at where the secret should come from instead.
 *
 * <p>Exit code: 0 translated and nothing unsafe found, 1 translated with
 * unsafe settings found, 2 called wrongly or nothing to translate.
 */
public final class Migrate {

    /** How much a finding matters. */
    public enum Level {
        /** A setting that weakens the connection's security. */
        UNSAFE,
        /** Translated, but it now means something slightly different. */
        CHANGED,
        /** No seclume equivalent - left out, with the reason. */
        NOT_TRANSLATED
    }

    /** One remark about the configuration. */
    public record Finding(Level level, String text) {
    }

    /** The translated properties, and what was found on the way. */
    public record Result(List<String> properties, List<Finding> findings) {

        /** Whether anything unsafe was found. */
        public boolean unsafe() {
            return findings.stream().anyMatch(finding -> finding.level() == Level.UNSAFE);
        }

        /** As printed: the properties, then the findings. */
        public String render() {
            StringBuilder out = new StringBuilder(); // seclume-allow: configuration text, the password never reaches it
            out.append("# seclume - translated").append(System.lineSeparator());
            for (String line : properties) {
                out.append(line).append(System.lineSeparator());
            }
            if (!findings.isEmpty()) {
                out.append(System.lineSeparator()).append("# findings").append(System.lineSeparator());
                for (Finding finding : findings) {
                    out.append("# ").append(String.format(Locale.ROOT, "%-15s", finding.level()))
                            .append(finding.text()).append(System.lineSeparator());
                }
            }
            return out.toString();
        }
    }

    private static final String DROPPED = "\u0000password";

    private Migrate() {
    }

    /** The command line: a properties file or a bare URL. */
    static int run(String argument, PrintStream out, PrintStream err) {
        Result result;
        try {
            if (argument.startsWith("jdbc:")) {
                result = translateUrl(argument);
            } else {
                Path file = Path.of(argument);
                if (!Files.isRegularFile(file)) {
                    err.println("no such file: " + argument);
                    return 2;
                }
                String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
                if (name.endsWith(".yml") || name.endsWith(".yaml")) {
                    err.println("YAML is not read - pass the JDBC URL itself, or the same "
                            + "settings as a .properties file");
                    return 2;
                }
                result = translate(load(file));
            }
        } catch (IllegalArgumentException e) {
            err.println(e.getMessage());
            return 2;
        }
        if (result.properties().isEmpty()) {
            err.println("found no data source to translate - no spring.datasource.url and no "
                    + "property holding a jdbc: URL");
            return 2;
        }
        out.print(result.render());
        return result.unsafe() ? 1 : 0;
    }

    /** A properties file, with every password value dropped as it is read. */
    static Map<String, String> load(Path file) {
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) { // seclume-allow: the application's configuration file; password values are dropped as it is read
            properties.load(reader);
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot read " + file + ": " + e.getMessage());
        }
        Map<String, String> config = new LinkedHashMap<>();
        for (String key : properties.stringPropertyNames()) {
            config.put(key, isPasswordKey(key) ? DROPPED : properties.getProperty(key));
        }
        properties.clear();
        return config;
    }

    /** One URL, as the data source {@code main}. */
    public static Result translateUrl(String url) {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("spring.datasource.url", url);
        return translate(config);
    }

    /**
     * A whole configuration: every data source in it, Spring's own under
     * {@code main} and any other property holding a JDBC URL under a name taken
     * from its key.
     */
    public static Result translate(Map<String, String> config) {
        List<String> lines = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<String, String> entry : config.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (DROPPED.equals(value) || value == null || !value.trim().startsWith("jdbc:")) {
                continue;
            }
            String prefix = prefixOf(key);
            String name = key.startsWith("spring.datasource.") ? "main" : nameOf(prefix);
            translateSource(name, value.trim(), prefix, config, lines, findings);
        }
        for (Map.Entry<String, String> entry : config.entrySet()) {
            if (DROPPED.equals(entry.getValue()) && !entry.getKey().contains("datasource")) {
                findings.add(new Finding(Level.UNSAFE, entry.getKey() + " holds a password in "
                        + "plain text - it is a String on the heap for the life of the "
                        + "application; seclume's starter names such properties at start "
                        + "(seclume.secret-guard)"));
            }
        }
        return new Result(lines, findings);
    }

    // ---- one data source -------------------------------------------------

    private static void translateSource(String name, String url, String prefix,
                                        Map<String, String> config, List<String> lines,
                                        List<Finding> findings) {
        String target = "seclume.datasources." + name + ".";
        Parsed parsed = parse(url, findings);
        if (parsed == null) {
            return;
        }
        // Properties beside the URL - Hikari's data-source-properties, and
        // the user - count as if they were in it.
        for (Map.Entry<String, String> entry : config.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith(prefix + "hikari.data-source-properties.")) {
                parsed.options.putIfAbsent(key.substring(
                        (prefix + "hikari.data-source-properties.").length()), entry.getValue());
            }
        }
        String user = firstOf(config, prefix + "username", prefix + "user");
        if (user == null) {
            user = parsed.options.remove("user");
        } else {
            parsed.options.remove("user");
        }
        boolean passwordSeen = parsed.passwordInUrl
                || DROPPED.equals(parsed.options.get("password"))
                || DROPPED.equals(config.get(prefix + "password"));
        parsed.options.remove("password");

        Map<String, String> seclume = new LinkedHashMap<>();
        switch (parsed.kind) {
            case "postgresql" -> postgres(parsed.options, seclume, findings);
            case "mysql" -> mysql(parsed.options, seclume, findings);
            case "sqlserver" -> sqlServer(parsed.options, seclume, findings);
            default -> oracle(parsed, seclume, findings);
        }
        if (parsed.hosts.contains(".rds.amazonaws.com") && !seclume.containsKey("tlsRootCert")
                && !"off".equals(seclume.get("tls"))) {
            seclume.put("tlsRootCert", "aws-rds");
            findings.add(new Finding(Level.CHANGED, name + ": an RDS host - tlsRootCert=aws-rds "
                    + "uses the RDS CA bundle that ships with seclume, so verify-full needs no "
                    + "trust store change"));
        }
        for (String left : parsed.options.keySet()) {
            findings.add(new Finding(Level.NOT_TRANSLATED, name + ": " + left
                    + " - no seclume equivalent, left out"));
        }

        StringBuilder out = new StringBuilder(parsed.tnsAlias != null // seclume-allow: a URL without its password
                ? "jdbc:seclume:oracle:tns:" + parsed.tnsAlias
                : "jdbc:seclume:" + parsed.kind + "://" + parsed.hosts + "/" + parsed.database);
        char separator = '?';
        for (Map.Entry<String, String> option : seclume.entrySet()) {
            out.append(separator).append(option.getKey()).append('=').append(option.getValue());
            separator = '&';
        }
        lines.add(target + "url=" + out);
        if (user != null) {
            lines.add(target + "username=" + user);
        }
        lines.add(target + "secret-uri=file:/run/secrets/" + name + "-db-password");
        findings.add(new Finding(passwordSeen ? Level.UNSAFE : Level.CHANGED, name + ": "
                + (passwordSeen ? "the password stood in the configuration - "
                : "the password comes from a secret provider now - ")
                + "put it into /run/secrets/" + name + "-db-password, or pick another "
                + "provider (vault, the cloud vaults, dpapi ... - see PROVIDERS.md)"));
        pool(prefix, target, config, lines, findings, name);
    }

    private static void postgres(Map<String, String> in, Map<String, String> out,
                                 List<Finding> findings) {
        String sslmode = lower(in.remove("sslmode"));
        String ssl = lower(in.remove("ssl"));
        String factory = in.remove("sslfactory");
        if (factory != null && factory.contains("NonValidatingFactory")) {
            out.put("tls", "require");
            findings.add(new Finding(Level.UNSAFE, "sslfactory=NonValidatingFactory accepts any "
                    + "certificate - translated to tls=require, which says so; tlsRootCert or "
                    + "tlsPin keep the check without a trust store change"));
        } else if (sslmode != null) {
            tlsMode(sslmode, out, findings, "sslmode");
        } else if ("true".equals(ssl)) {
            // pgjdbc: ssl=true without sslmode means verify-full.
            out.put("tls", "verify-full");
        } else {
            out.put("tls", "prefer");
            findings.add(new Finding(Level.UNSAFE, "no sslmode: pgjdbc prefers TLS without "
                    + "checking the certificate, and so does this translation (tls=prefer) - "
                    + "tls=verify-full is the setting that authenticates the server"));
        }
        move(in, "sslrootcert", out, "tlsRootCert");
        move(in, "sslnegotiation", out, "tlsNegotiation");
        move(in, "ApplicationName", out, "applicationName");
        seconds(in, "connectTimeout", out);
        target(in, out, findings);
        clientCertificate(in, "sslcert", "sslkey", out, findings);
        for (String ignored : List.of("prepareThreshold", "preparedStatementCacheQueries",
                "sslpassword", "loginTimeout", "tcpKeepAlive")) {
            if (in.remove(ignored) != null) {
                findings.add(new Finding(Level.CHANGED, ignored + " - handled by seclume on its "
                        + "own (plan cache, keepalive, timeouts), dropped"));
            }
        }
    }

    private static void mysql(Map<String, String> in, Map<String, String> out,
                              List<Finding> findings) {
        String mode = lower(in.remove("sslMode"));
        String useSsl = lower(in.remove("useSSL"));
        String verify = lower(in.remove("verifyServerCertificate"));
        if (mode != null) {
            switch (mode.replace('_', '-')) {
                case "disabled" -> tlsMode("disable", out, findings, "sslMode");
                case "preferred" -> tlsMode("prefer", out, findings, "sslMode");
                case "required" -> tlsMode("require", out, findings, "sslMode");
                case "verify-ca" -> tlsMode("verify-ca", out, findings, "sslMode");
                default -> tlsMode("verify-full", out, findings, "sslMode");
            }
        } else if ("false".equals(useSsl)) {
            tlsMode("disable", out, findings, "useSSL");
        } else if ("true".equals(useSsl)) {
            tlsMode("false".equals(verify) ? "require" : "verify-full", out, findings, "useSSL");
        } else {
            tlsMode("prefer", out, findings, "sslMode (not set)");
        }
        String retrieval = lower(in.remove("allowPublicKeyRetrieval"));
        if ("true".equals(retrieval)) {
            out.put("allowPublicKeyRetrieval", "true");
            String tls = out.get("tls");
            if (!"require".equals(tls) && !"verify-full".equals(tls)) {
                findings.add(new Finding(Level.UNSAFE, "allowPublicKeyRetrieval=true without "
                        + "required TLS: whoever sits in between hands over their own key and "
                        + "reads the password"));
            }
        }
        move(in, "connectionAttributes", out, null);
        seconds(in, "connectTimeout", out, 1);  // Connector/J counts milliseconds already
        // Multi-row inserts change what a failing batch leaves behind, so
        // they stay what the configuration asked for: on only when it was on.
        if ("true".equalsIgnoreCase(in.remove("rewriteBatchedStatements"))) {
            out.put("rewriteBatchedInserts", "true");
        }
        for (String ignored : List.of("serverTimezone", "characterEncoding", "useUnicode",
                "cachePrepStmts", "prepStmtCacheSize", "prepStmtCacheSqlLimit",
                "useServerPrepStmts", "autoReconnect",
                "zeroDateTimeBehavior", "tcpKeepAlive")) {
            if (in.remove(ignored) != null) {
                findings.add(new Finding(Level.CHANGED, ignored + " - not needed: seclume "
                        + "prepares, caches, batches and keeps connections alive on its own"));
            }
        }
        if (in.containsKey("trustCertificateKeyStoreUrl")) {
            in.remove("trustCertificateKeyStoreUrl");
            in.remove("trustCertificateKeyStorePassword");
            findings.add(new Finding(Level.CHANGED, "trustCertificateKeyStoreUrl - export the CA "
                    + "as PEM and name it with tlsRootCert=..."));
        }
    }

    private static void sqlServer(Map<String, String> in, Map<String, String> out,
                                  List<Finding> findings) {
        String encrypt = lower(in.remove("encrypt"));
        if ("strict".equals(encrypt)) {
            out.put("tds", "8.0");
        } else if ("false".equals(encrypt) || "optional".equals(encrypt)) {
            findings.add(new Finding(Level.CHANGED, "encrypt=" + encrypt + " - seclume always "
                    + "encrypts; the server needs a certificate the client can check"));
        }
        if ("true".equals(lower(in.remove("trustServerCertificate")))) {
            out.put("trustServerCertificate", "true");
            findings.add(new Finding(Level.UNSAFE, "trustServerCertificate=true accepts any "
                    + "certificate - kept, but tlsRootCert=<ca.pem> or tlsPin=sha256/... "
                    + "(seclume-verify --print-pin) keep the check instead"));
        }
        move(in, "applicationName", out, "applicationName");
        seconds(in, "loginTimeout", out);
        if ("false".equals(lower(in.remove("sendStringParametersAsUnicode")))) {
            findings.add(new Finding(Level.CHANGED, "sendStringParametersAsUnicode=false - "
                    + "seclume decides per parameter instead (varchar where the column is, "
                    + "for ASCII text); dropped"));
        }
        for (String unsupported : List.of("integratedSecurity", "authentication",
                "instanceName")) {
            String value = in.remove(unsupported);
            if (value != null) {
                findings.add(new Finding(Level.NOT_TRANSLATED, unsupported + "=" + value
                        + " - not supported yet (see README, \"What it does not do yet\")"));
            }
        }
        in.remove("hostNameInCertificate");
    }

    private static void oracle(Parsed parsed, Map<String, String> out, List<Finding> findings) {
        if (parsed.tcps) {
            out.put("tls", "verify-full");
        }
        if (parsed.sid) {
            findings.add(new Finding(Level.CHANGED, "the SID " + parsed.database + " is used as "
                    + "a service name - if the database only knows it as a SID, register a "
                    + "service for it"));
        }
        parsed.options.remove("oracle.jdbc.timezoneAsRegion");
    }

    // ---- shared translations ---------------------------------------------

    private static void tlsMode(String mode, Map<String, String> out, List<Finding> findings,
                                String from) {
        switch (mode) {
            case "disable", "disabled" -> {
                out.put("tls", "off");
                findings.add(new Finding(Level.UNSAFE, from + " switches encryption off - the "
                        + "password and every row travel in the clear"));
            }
            case "allow", "prefer", "preferred" -> {
                out.put("tls", "prefer");
                findings.add(new Finding(Level.UNSAFE, from + "=" + mode + " encrypts only when "
                        + "the server offers it and checks nothing - it stops a listener, not "
                        + "a man in the middle; tls=verify-full does"));
            }
            case "require", "required" -> {
                out.put("tls", "require");
                findings.add(new Finding(Level.UNSAFE, from + "=" + mode + " encrypts but "
                        + "checks no certificate - tls=verify-full, with tlsRootCert when the "
                        + "CA is your own"));
            }
            case "verify-ca" -> {
                out.put("tls", "verify-full");
                findings.add(new Finding(Level.CHANGED, from + "=verify-ca became verify-full: "
                        + "the host name is checked too, which is stricter"));
            }
            default -> out.put("tls", "verify-full");
        }
    }

    private static void target(Map<String, String> in, Map<String, String> out,
                               List<Finding> findings) {
        String target = in.remove("targetServerType");
        if (target == null) {
            return;
        }
        switch (target.toLowerCase(Locale.ROOT)) {
            case "primary", "master" -> out.put("targetServerType", "primary");
            case "secondary", "slave" -> out.put("targetServerType", "secondary");
            case "any" -> { }
            default -> findings.add(new Finding(Level.NOT_TRANSLATED, "targetServerType="
                    + target + " - seclume knows primary and secondary"));
        }
    }

    private static void clientCertificate(Map<String, String> in, String certKey, String keyKey,
                                          Map<String, String> out, List<Finding> findings) {
        String cert = in.remove(certKey);
        String key = in.remove(keyKey);
        if (cert == null && key == null) {
            return;
        }
        if (cert != null) {
            out.put("clientCert", cert);
        }
        if (key != null) {
            out.put("clientKey-provider", "file");
            out.put("clientKey-path", key);
        }
        out.put("tlsStack", "seclume");
        findings.add(new Finding(Level.CHANGED, "client certificate: seclume signs with a "
                + "P-256 key kept off the heap, on its own TLS stack (tlsStack=seclume) - an RSA "
                + "key is refused"));
    }

    private static void pool(String prefix, String target, Map<String, String> config,
                             List<String> lines, List<Finding> findings, String name) {
        String hikari = prefix + "hikari.";
        Map<String, String> durations = Map.of(
                "connection-timeout", "connection-timeout", "idle-timeout", "idle-timeout",
                "max-lifetime", "max-lifetime", "keepalive-time", "keepalive-time",
                "validation-timeout", "validation-timeout",
                "leak-detection-threshold", "leak-detection-threshold");
        for (Map.Entry<String, String> entry : config.entrySet()) {
            if (!entry.getKey().startsWith(hikari)
                    || entry.getKey().startsWith(hikari + "data-source-properties.")) {
                continue;
            }
            String setting = kebab(entry.getKey().substring(hikari.length()));
            String value = entry.getValue().trim();
            if (setting.equals("maximum-pool-size") || setting.equals("minimum-idle")) {
                lines.add(target + "pool." + setting + "=" + value);
            } else if (durations.containsKey(setting)) {
                lines.add(target + "pool." + setting + "="
                        + (value.matches("\\d+") ? value + "ms" : value));
            } else if (setting.equals("connection-test-query")) {
                findings.add(new Finding(Level.CHANGED, name + ": connection-test-query - "
                        + "seclume checks a connection with the protocol's own ping, dropped"));
            } else if (!setting.equals("pool-name") && !setting.equals("driver-class-name")) {
                findings.add(new Finding(Level.NOT_TRANSLATED, name + ": hikari." + setting
                        + " - no pool equivalent, left out"));
            }
        }
    }

    // ---- parsing the vendors' URLs ---------------------------------------

    private static final class Parsed {
        String kind;
        String hosts;
        String database = "";
        final Map<String, String> options = new LinkedHashMap<>();
        boolean passwordInUrl;
        boolean tcps;
        boolean sid;
        /** An Oracle net service name, {@code @ORDERS} - resolved through tnsnames.ora. */
        String tnsAlias;
    }

    private static Parsed parse(String url, List<Finding> findings) {
        Parsed parsed = new Parsed();
        String lower = url.toLowerCase(Locale.ROOT);
        if (lower.startsWith("jdbc:postgresql:")) {
            parsed.kind = "postgresql";
            slashForm(url.substring("jdbc:postgresql:".length()), "5432", parsed);
        } else if (lower.startsWith("jdbc:mysql:") || lower.startsWith("jdbc:mariadb:")) {
            parsed.kind = "mysql";
            String rest = url.substring(url.indexOf(':', 5) + 1);
            for (String variant : List.of("loadbalance:", "replication:", "aurora:",
                    "sequential:")) {
                if (rest.startsWith(variant)) {
                    rest = rest.substring(variant.length());
                    findings.add(new Finding(Level.CHANGED, "the " + variant.replace(":", "")
                            + " URL form became a host list tried in order - add "
                            + "targetServerType or hostSelection=quality as needed"));
                }
            }
            slashForm(rest, "3306", parsed);
        } else if (lower.startsWith("jdbc:sqlserver:")) {
            parsed.kind = "sqlserver";
            sqlServerForm(url.substring("jdbc:sqlserver:".length()), parsed);
        } else if (lower.startsWith("jdbc:oracle:thin:")) {
            parsed.kind = "oracle";
            if (!oracleForm(url.substring("jdbc:oracle:thin:".length()), parsed, findings)) {
                return null;
            }
        } else {
            throw new IllegalArgumentException("not a URL seclume can translate: "
                    + url.substring(0, Math.min(url.length(), 30))
                    + " - it reads jdbc:postgresql, jdbc:mysql, jdbc:mariadb, jdbc:sqlserver "
                    + "and jdbc:oracle:thin");
        }
        if (parsed.options.containsKey("password")) {
            parsed.options.put("password", DROPPED);
        }
        return parsed;
    }

    /** {@code //host[:port][,host[:port]]/database?query} - PostgreSQL and MySQL. */
    private static void slashForm(String rest, String port, Parsed parsed) {
        int question = rest.indexOf('?');
        String query = question < 0 ? "" : rest.substring(question + 1);
        String address = question < 0 ? rest : rest.substring(0, question);
        if (!address.startsWith("//")) {
            parsed.hosts = "localhost:" + port;
            parsed.database = address;
        } else {
            address = address.substring(2);
            int slash = address.indexOf('/');
            parsed.hosts = withPorts(slash < 0 ? address : address.substring(0, slash), port);
            parsed.database = slash < 0 ? "" : address.substring(slash + 1);
        }
        for (String pair : query.split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                parsed.options.put(pair.substring(0, equals),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
    }

    /** {@code //host[\instance][:port];key=value;...} - mssql-jdbc. */
    private static void sqlServerForm(String rest, Parsed parsed) {
        String[] parts = rest.split(";");
        String address = parts[0].startsWith("//") ? parts[0].substring(2) : parts[0];
        for (int i = 1; i < parts.length; i++) {
            int equals = parts[i].indexOf('=');
            if (equals > 0) {
                parsed.options.put(parts[i].substring(0, equals).trim(),
                        parts[i].substring(equals + 1).trim());
            }
        }
        int backslash = address.indexOf('\\');
        if (backslash >= 0) {
            String instance = address.substring(backslash + 1);
            int colon = instance.indexOf(':');
            parsed.options.put("instanceName", colon < 0 ? instance : instance.substring(0, colon));
            address = address.substring(0, backslash) + (colon < 0 ? "" : instance.substring(colon));
        }
        String server = parsed.options.remove("serverName");
        String port = parsed.options.remove("portNumber");
        if (address.isEmpty() && server != null) {
            address = server;
        }
        if (port != null && !address.contains(":")) {
            address = address + ":" + port;
        }
        parsed.hosts = withPorts(address, "1433");
        String database = parsed.options.remove("databaseName");
        if (database == null) {
            database = parsed.options.remove("database");
        }
        parsed.database = database == null ? "master" : database;
    }

    /** {@code [user/password]@//host:port/service}, {@code @host:port:SID}, {@code @tcps://...}. */
    private static boolean oracleForm(String rest, Parsed parsed, List<Finding> findings) {
        int at = rest.indexOf('@');
        if (at > 0) {
            String credentials = rest.substring(0, at);
            int slash = credentials.indexOf('/');
            parsed.options.put("user", slash < 0 ? credentials : credentials.substring(0, slash));
            parsed.passwordInUrl = slash >= 0;
        }
        String address = at < 0 ? rest : rest.substring(at + 1);
        int question = address.indexOf('?');
        if (question >= 0) {
            for (String pair : address.substring(question + 1).split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    parsed.options.put(pair.substring(0, equals), pair.substring(equals + 1));
                }
            }
            address = address.substring(0, question);
        }
        if (address.startsWith("(")) {
            findings.add(new Finding(Level.NOT_TRANSLATED, "a TNS descriptor "
                    + "(DESCRIPTION=...) - put it into tnsnames.ora under an alias and use "
                    + "jdbc:seclume:oracle:tns:ALIAS?tnsAdmin=<its directory>"));
            return false;
        }
        if (!address.startsWith("//") && !address.contains(":") && !address.contains("/")) {
            parsed.tnsAlias = address;
            parsed.hosts = "";
            findings.add(new Finding(Level.CHANGED, "the net service name " + address + " is "
                    + "looked up in tnsnames.ora - name its directory with tnsAdmin=..., "
                    + "-Doracle.net.tns_admin or TNS_ADMIN"));
            return true;
        }
        String lowerAddress = address.toLowerCase(Locale.ROOT);
        if (lowerAddress.startsWith("tcps://")) {
            parsed.tcps = true;
            address = "//" + address.substring("tcps://".length());
        } else if (lowerAddress.startsWith("tcp://")) {
            address = "//" + address.substring("tcp://".length());
        }
        if (address.startsWith("//")) {
            address = address.substring(2);
            int slash = address.indexOf('/');
            parsed.hosts = withPorts(slash < 0 ? address : address.substring(0, slash),
                    parsed.tcps ? "2484" : "1521");
            parsed.database = slash < 0 ? "" : address.substring(slash + 1);
        } else {
            String[] pieces = address.split(":");
            parsed.hosts = pieces[0] + ":" + (pieces.length > 1 ? pieces[1] : "1521");
            parsed.database = pieces.length > 2 ? pieces[2] : "";
            parsed.sid = pieces.length > 2;
        }
        return true;
    }

    // ---- small things ----------------------------------------------------

    private static String withPorts(String hosts, String port) {
        List<String> each = new ArrayList<>();
        for (String host : hosts.split(",")) {
            String trimmed = host.trim();
            boolean hasPort = trimmed.startsWith("[") ? trimmed.contains("]:")
                    : trimmed.contains(":");
            each.add(hasPort ? trimmed : trimmed + ":" + port);
        }
        return String.join(",", each);
    }

    private static void move(Map<String, String> in, String from, Map<String, String> out,
                             String to) {
        String value = in.remove(from);
        if (value != null && to != null) {
            out.put(to, value);
        }
    }

    private static void seconds(Map<String, String> in, String key, Map<String, String> out) {
        seconds(in, key, out, 1000);
    }

    /** A timeout in the vendor's unit, as seclume's connectTimeout in milliseconds. */
    private static void seconds(Map<String, String> in, String key, Map<String, String> out,
                                int factor) {
        String value = in.remove(key);
        if (value != null && value.trim().matches("\\d+") && !value.trim().equals("0")) {
            out.put("connectTimeout", String.valueOf(Long.parseLong(value.trim()) * factor));
        }
    }

    private static String firstOf(Map<String, String> config, String... keys) {
        for (String key : keys) {
            String value = config.get(key);
            if (value != null && !DROPPED.equals(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private static String lower(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    /** {@code maximumPoolSize} and {@code maximum-pool-size} alike. */
    private static String kebab(String key) {
        return key.replaceAll("([a-z])([A-Z])", "$1-$2").toLowerCase(Locale.ROOT);
    }

    /** The key's prefix up to the URL property: {@code spring.datasource.} for {@code spring.datasource.url}. */
    private static String prefixOf(String key) {
        int dot = key.lastIndexOf('.');
        return dot < 0 ? "" : key.substring(0, dot + 1);
    }

    /** A data source name from a prefix: {@code app.reporting.datasource.} becomes {@code reporting}. */
    private static String nameOf(String prefix) {
        String[] parts = prefix.split("\\.");
        for (int i = parts.length - 1; i >= 0; i--) {
            if (!parts[i].isEmpty() && !parts[i].equals("datasource") && !parts[i].equals("jdbc")
                    && !parts[i].equals("hikari")) {
                return parts[i].replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
            }
        }
        return "main";
    }

    private static boolean isPasswordKey(String key) {
        String lower = key.toLowerCase(Locale.ROOT);
        return lower.endsWith("password") || lower.endsWith("passwd") || lower.endsWith("pwd")
                || lower.endsWith(".secret");
    }
}
