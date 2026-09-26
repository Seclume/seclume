package space.seclume.oracle.jdbc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * {@code tnsnames.ora} and connect descriptors - how Oracle connections are
 * configured in practice.
 *
 * <pre>
 *   jdbc:seclume:oracle:tns:ORDERS?user=app&amp;provider=file&amp;path=...&amp;tnsAdmin=/etc/oracle
 * </pre>
 *
 * The alias is looked up in {@code tnsnames.ora} in the directory named by
 * {@code tnsAdmin}, the system property {@code oracle.net.tns_admin}, or the
 * environment variable {@code TNS_ADMIN}, in that order. Its descriptor
 * becomes the URL the driver already understands: every {@code ADDRESS} a host
 * of the list, {@code SERVICE_NAME} the service, {@code PROTOCOL=TCPS}
 * encryption. What a descriptor can say beyond that - load balancing,
 * {@code FAILOVER_MODE}, a {@code SID} - is refused by name rather than
 * ignored.
 */
final class TnsNames {

    static final String TNS = "tns:";

    private TnsNames() {
    }

    /** {@code url} with a {@code tns:} alias replaced by the host list and service it names. */
    static String resolve(String url, Properties properties) throws SQLException {
        String rest = url.substring(OraUrl.PREFIX.length());
        if (!rest.regionMatches(true, 0, TNS, 0, TNS.length())) {
            return url;
        }
        rest = rest.substring(TNS.length());
        int question = rest.indexOf('?');
        String alias = question < 0 ? rest : rest.substring(0, question);
        String query = question < 0 ? "" : rest.substring(question + 1);
        String directory = option(query, properties, "tnsAdmin");
        if (directory == null) {
            directory = System.getProperty("oracle.net.tns_admin");
        }
        if (directory == null) {
            directory = System.getenv("TNS_ADMIN"); // seclume-allow: a directory name, Oracle's own convention - never a secret
        }
        if (directory == null) {
            throw new SQLException("tns:" + alias + " - where is tnsnames.ora? Name its directory "
                    + "with tnsAdmin=..., -Doracle.net.tns_admin or TNS_ADMIN", "08001");
        }
        Path file = Path.of(directory, "tnsnames.ora");
        String text;
        try {
            text = Files.readString(file, StandardCharsets.UTF_8); // seclume-allow: a names file, addresses only - never a secret
        } catch (IOException e) {
            throw new SQLException("cannot read " + file + ": " + e.getMessage(), "08001", e);
        }
        String descriptor = entries(text).get(alias.toUpperCase(Locale.ROOT));
        if (descriptor == null) {
            throw new SQLException("tns:" + alias + " is not in " + file, "08001");
        }
        Target target = target(descriptor);
        String options = query.isEmpty() ? "" : query;
        if (target.tcps() && option(query, properties, "tls") == null) {
            options = options.isEmpty() ? "tls=verify-full" : options + "&tls=verify-full";
        }
        return OraUrl.PREFIX + "//" + String.join(",", target.hosts()) + "/" + target.service()
                + (options.isEmpty() ? "" : "?" + options);
    }

    /** Where a descriptor points: host:port list, service, and whether it is TCPS. */
    record Target(List<String> hosts, String service, boolean tcps) {
    }

    /** Every alias in a tnsnames.ora, upper-cased, with its descriptor. */
    static Map<String, String> entries(String text) {
        Map<String, String> entries = new LinkedHashMap<>();
        StringBuilder clean = new StringBuilder(text.length()); // seclume-allow: a names file, no secret in it
        for (String line : text.split("\\R")) {
            int hash = line.indexOf('#');
            clean.append(hash < 0 ? line : line.substring(0, hash)).append('\n');
        }
        String all = clean.toString();
        int at = 0;
        while (at < all.length()) {
            int equals = all.indexOf('=', at);
            if (equals < 0) {
                break;
            }
            String names = all.substring(at, equals).trim();
            int open = all.indexOf('(', equals);
            if (open < 0) {
                break;
            }
            int depth = 0;
            int end = open;
            for (; end < all.length(); end++) {
                char c = all.charAt(end);
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                    if (depth == 0) {
                        break;
                    }
                }
            }
            String descriptor = all.substring(open, Math.min(end + 1, all.length()))
                    .replaceAll("\\s+", "");
            for (String name : names.split(",")) {
                String trimmed = name.trim();
                if (!trimmed.isEmpty() && !trimmed.toUpperCase(Locale.ROOT).startsWith("IFILE")) {
                    entries.put(trimmed.toUpperCase(Locale.ROOT), descriptor);
                }
            }
            at = end + 1;
        }
        return entries;
    }

    /** The addresses and the service of one descriptor. */
    static Target target(String descriptor) throws SQLException {
        String upper = descriptor.toUpperCase(Locale.ROOT);
        for (String refused : List.of("FAILOVER_MODE", "(SID=", "SOURCE_ROUTE=YES")) {
            if (upper.contains(refused)) {
                throw new SQLException("the descriptor says " + refused.replace("(", "")
                        + ", which seclume does not do - " + (refused.contains("SID")
                        ? "use the SERVICE_NAME" : "remove it"), "08001");
            }
        }
        List<String> hosts = new ArrayList<>();
        boolean tcps = false;
        int at = 0;
        while ((at = upper.indexOf("(ADDRESS=", at)) >= 0) {
            int end = closing(upper, at);
            String address = upper.substring(at, end);
            String host = value(descriptor.substring(at, end), "HOST");
            String port = value(address, "PORT");
            String protocol = value(address, "PROTOCOL");
            if (host == null) {
                throw new SQLException("an ADDRESS without HOST: " + address, "08001");
            }
            if ("TCPS".equals(protocol)) {
                tcps = true;
            } else if (protocol != null && !"TCP".equals(protocol)) {
                throw new SQLException("PROTOCOL=" + protocol + " - seclume speaks TCP and TCPS",
                        "08001");
            }
            hosts.add(host + ":" + (port == null ? "1521" : port));
            at = end;
        }
        String service = value(descriptor, "SERVICE_NAME");
        if (hosts.isEmpty() || service == null) {
            throw new SQLException("the descriptor names no " + (hosts.isEmpty() ? "ADDRESS"
                    : "SERVICE_NAME") + ": " + descriptor, "08001");
        }
        return new Target(hosts, service, tcps);
    }

    /** The value of {@code (KEY=value)} in a descriptor, as written. */
    private static String value(String descriptor, String key) {
        String upper = descriptor.toUpperCase(Locale.ROOT);
        int at = upper.indexOf("(" + key + "=");
        if (at < 0) {
            return null;
        }
        int start = at + key.length() + 2;
        int end = descriptor.indexOf(')', start);
        return end < 0 ? null : descriptor.substring(start, end).trim();
    }

    private static int closing(String text, int open) {
        int depth = 0;
        for (int i = open; i < text.length(); i++) {
            if (text.charAt(i) == '(') {
                depth++;
            } else if (text.charAt(i) == ')' && --depth == 0) {
                return i + 1;
            }
        }
        return text.length();
    }

    private static String option(String query, Properties properties, String name) {
        if (properties != null && properties.getProperty(name) != null) {
            return properties.getProperty(name);
        }
        for (String pair : query.split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0 && pair.substring(0, equals).equalsIgnoreCase(name)) {
                return pair.substring(equals + 1);
            }
        }
        return null;
    }
}
