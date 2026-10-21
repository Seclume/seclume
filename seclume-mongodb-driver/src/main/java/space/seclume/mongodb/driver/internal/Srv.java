package space.seclume.mongodb.driver.internal;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import com.mongodb.MongoConfigurationException;

/**
 * {@code mongodb+srv://}: the hosts from DNS SRV records, a few options from a
 * TXT record - turned into the {@code mongodb://} URL they stand for. From the
 * initial DNS seedlist discovery specification
 * (github.com/mongodb/specifications, source/initial-dns-seedlist-discovery).
 *
 * <p>The checks are what keeps DNS from sending the login elsewhere: a host
 * the SRV records name has to lie within the domain the URL names, and the
 * TXT record may set only {@code authSource}, {@code replicaSet} and
 * {@code loadBalanced}. TLS is on regardless - with seclume it always is.
 */
public final class Srv {

    /** Looks records up; the JDK's DNS by default, a stand-in in tests. */
    public interface Resolver {
        /** {@code target:port} for each SRV record of {@code name}, or none. */
        List<String> srv(String name);

        /** The TXT records of {@code name}, or none. */
        List<String> txt(String name);
    }

    private static final java.util.regex.Pattern HOST_NAME = java.util.regex.Pattern.compile(
            "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*");
    private static final java.util.regex.Pattern TXT_VALUE = java.util.regex.Pattern.compile(
            "[A-Za-z0-9_.$-]{1,255}");
    private static final java.util.regex.Pattern PORT = java.util.regex.Pattern.compile(
            "[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]");

    private static final Set<String> TXT_OPTIONS = Set.of("authsource", "replicaset",
            "loadbalanced");

    private Srv() {
    }

    /**
     * The {@code mongodb://} URL a {@code mongodb+srv://} one stands for; any
     * other URL as it is.
     */
    public static String expand(String url, Resolver resolver) {
        if (!url.startsWith("mongodb+srv://")) {
            return url;
        }
        String rest = url.substring("mongodb+srv://".length());
        int slash = rest.indexOf('/');
        String authority = slash < 0 ? rest : rest.substring(0, slash);
        String path = slash < 0 ? "/" : rest.substring(slash);
        int at = authority.lastIndexOf('@');
        String userInfo = at < 0 ? "" : authority.substring(0, at + 1);
        String host = authority.substring(at + 1).toLowerCase(Locale.ROOT);
        if (host.contains(",") || host.contains(":")) {
            throw new MongoConfigurationException("a mongodb+srv:// URL names one host and no "
                    + "port: " + host);
        }
        Map<String, String> query = query(path);
        String service = query.getOrDefault("srvservicename", "mongodb");
        List<String> hosts = new ArrayList<>(seeds(host, service, resolver));
        if (query.containsKey("srvmaxhosts")) {
            int max;
            try {
                max = Integer.parseInt(query.get("srvmaxhosts"));
            } catch (NumberFormatException e) {
                throw new MongoConfigurationException("srvMaxHosts is not a number: "
                        + query.get("srvmaxhosts"));
            }
            if (max > 0 && hosts.size() > max) {
                Collections.shuffle(hosts);
                hosts = hosts.subList(0, max);
            }
        }
        StringBuilder options = new StringBuilder();
        for (Map.Entry<String, String> option : txtOptions(host, resolver).entrySet()) {
            if (!query.containsKey(option.getKey())) {           // the URL's own win
                append(options, option.getKey() + "=" + option.getValue());
            }
        }
        String ownQuery = path.contains("?") ? path.substring(path.indexOf('?') + 1) : "";
        for (String pair : ownQuery.split("&")) {
            String key = pair.contains("=") ? pair.substring(0, pair.indexOf('='))
                    .toLowerCase(Locale.ROOT) : pair.toLowerCase(Locale.ROOT);
            if (!pair.isEmpty() && !key.equals("srvservicename") && !key.equals("srvmaxhosts")) {
                append(options, pair);
            }
        }
        append(options, "tls=true");
        String database = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
        return "mongodb://" + userInfo + String.join(",", hosts) + database + "?" + options;
    }

    /** The host and the service name of a {@code mongodb+srv://} URL, for asking again. */
    public record Name(String host, String service) {

        public static Name of(String url) {
            String rest = url.substring("mongodb+srv://".length());
            int slash = rest.indexOf('/');
            String authority = slash < 0 ? rest : rest.substring(0, slash);
            String host = authority.substring(authority.lastIndexOf('@') + 1)
                    .toLowerCase(Locale.ROOT);
            return new Name(host, query(slash < 0 ? "/" : rest.substring(slash))
                    .getOrDefault("srvservicename", "mongodb"));
        }
    }

    /** The SRV targets of {@code host}, each checked to lie within its domain. */
    public static List<String> seeds(String host, String service, Resolver resolver) {
        String[] labels = host.split("\\.");
        List<String> found = resolver.srv("_" + service + "._tcp." + host);
        if (found.isEmpty()) {
            throw new MongoConfigurationException("no SRV records for _" + service + "._tcp."
                    + host);
        }
        // The domain a target has to end in: the host without its first label;
        // a host of one or two labels is itself the domain, and a target has to
        // be below it.
        String domain = labels.length >= 3 ? host.substring(host.indexOf('.')) : "." + host;
        List<String> seeds = new ArrayList<>();
        for (String target : found) {
            int colon = target.lastIndexOf(':');
            String port = colon < 0 ? "" : target.substring(colon + 1);
            String name = target.substring(0, Math.max(colon, 0)).toLowerCase(Locale.ROOT);
            if (name.endsWith(".")) {
                name = name.substring(0, name.length() - 1);
            }
            // Only a host name and a port go into the URL: a target that
            // carried '/', '?', '@' or ',' would end in the domain and still
            // name another host, or options, once it is part of the URL.
            if (!HOST_NAME.matcher(name).matches() || !PORT.matcher(port).matches()) {
                throw new MongoConfigurationException("the SRV record of " + host + " names "
                        + "'" + target + "', which is not a host name and port");
            }
            if (!name.endsWith(domain) || name.equals(domain.substring(1))) {
                throw new MongoConfigurationException("the SRV record of " + host + " names "
                        + name + ", which is not within " + domain.substring(1)
                        + " - refused, so that DNS cannot send the login elsewhere");
            }
            seeds.add(name + ":" + port);
        }
        return seeds;
    }

    static Map<String, String> txtOptions(String host, Resolver resolver) {
        List<String> records = resolver.txt(host);
        if (records.size() > 1) {
            throw new MongoConfigurationException("more than one TXT record for " + host);
        }
        Map<String, String> options = new LinkedHashMap<>();
        if (records.isEmpty()) {
            return options;
        }
        for (String pair : records.get(0).split("&")) {
            if (pair.isBlank()) {
                continue;
            }
            int equals = pair.indexOf('=');
            String key = (equals < 0 ? pair : pair.substring(0, equals)).toLowerCase(Locale.ROOT);
            if (!TXT_OPTIONS.contains(key)) {
                throw new MongoConfigurationException("the TXT record of " + host
                        + " sets '" + key + "'; only authSource, replicaSet and loadBalanced "
                        + "may come from DNS");
            }
            String value = equals < 0 ? "" : pair.substring(equals + 1);
            // Into the URL as it is: nothing that could end the value and start
            // something else there.
            if (!TXT_VALUE.matcher(value).matches()) {
                throw new MongoConfigurationException("the TXT record of " + host
                        + " sets " + key + " to '" + value + "', which is not a plain name");
            }
            options.put(key, value);
        }
        return options;
    }

    private static Map<String, String> query(String path) {
        Map<String, String> query = new LinkedHashMap<>();
        int question = path.indexOf('?');
        if (question < 0) {
            return query;
        }
        for (String pair : path.substring(question + 1).split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                query.put(pair.substring(0, equals).toLowerCase(Locale.ROOT),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
        return query;
    }

    private static void append(StringBuilder options, String pair) {
        if (!options.isEmpty()) {
            options.append('&');
        }
        options.append(pair);
    }

    /** The JDK's DNS client (JNDI, module jdk.naming.dns). */
    public static Resolver dns() {
        return new Resolver() {
            @Override
            public List<String> srv(String name) {
                List<String> targets = new ArrayList<>();
                for (String record : lookUp(name, "SRV")) {
                    // priority weight port target
                    String[] fields = record.trim().split("\\s+");
                    if (fields.length == 4) {
                        targets.add(fields[3] + ":" + fields[2]);
                    }
                }
                return targets;
            }

            @Override
            public List<String> txt(String name) {
                List<String> texts = new ArrayList<>();
                for (String record : lookUp(name, "TXT")) {
                    // A TXT record may come as several quoted strings: joined, as the spec says.
                    texts.add(record.replace("\" \"", "").replace("\"", ""));
                }
                return texts;
            }
        };
    }

    private static List<String> lookUp(String name, String type) {
        Hashtable<String, String> environment = new Hashtable<>();
        environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        environment.put("java.naming.provider.url", "dns:");
        List<String> values = new ArrayList<>();
        try {
            DirContext context = new InitialDirContext(environment);
            try {
                Attributes attributes = context.getAttributes(name, new String[] {type});
                Attribute attribute = attributes.get(type);
                if (attribute != null) {
                    NamingEnumeration<?> all = attribute.getAll();
                    while (all.hasMore()) {
                        values.add(String.valueOf(all.next()));
                    }
                }
            } finally {
                context.close();
            }
        } catch (NameNotFoundException none) {
            return values;
        } catch (NamingException e) {
            throw new MongoConfigurationException("DNS lookup of " + type + " " + name
                    + " failed: " + e.getMessage(), e);
        }
        return values;
    }
}
