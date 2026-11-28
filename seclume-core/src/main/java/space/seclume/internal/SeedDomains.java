package space.seclume.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Which discovered hosts a credential may go to: the configured ones - the
 * seeds - and nothing a server announces beyond them.
 *
 * <p>A MongoDB replica set names its members, a Kafka cluster its brokers, a
 * Patroni cluster its nodes. A driver connects to each and logs in - and one
 * compromised member, or a reconfiguration, could announce a host of its
 * choosing with a valid public certificate and collect the login. So
 * discovery may reorder, never extend: a host may be one of the seeds (on any
 * port), a host in a seed's parent domain ({@code a.db.example} admits
 * {@code b.db.example}), or a host under an explicitly configured suffix. A
 * seed written as an address admits that address only.
 */
public final class SeedDomains {

    private SeedDomains() {
    }

    /** Whether {@code host} may get the credential, given the seeds and the extra suffixes. */
    public static boolean admits(String host, List<String> seeds, List<String> extra) {
        String name = host.toLowerCase(Locale.ROOT);
        for (String seed : seeds) {
            if (name.equals(seed)) {
                return true;
            }
            int dot = seed.indexOf('.');
            boolean literal = seed.chars().allMatch(ch -> ch == '.' || ch == ':'
                    || Character.digit(ch, 16) >= 0) || seed.startsWith("[");
            if (!literal && dot > 0 && seed.indexOf('.', dot + 1) > 0 // mutation-equivalent: that index is past dot, itself past 0: > 0 and >= 0 agree
                    && name.endsWith(seed.substring(dot))) {
                return true;
            }
        }
        for (String suffix : extra) {
            if (name.equals(suffix) || name.endsWith("." + suffix)) {
                return true;
            }
        }
        return false;
    }

    /** {@code a.example,*.b.example,.c.example} as suffixes, lower case, without the wildcard. */
    public static List<String> suffixes(String list) {
        List<String> out = new ArrayList<>();
        if (list == null) {
            return out;
        }
        for (String one : list.split(",")) {
            String suffix = one.strip().toLowerCase(Locale.ROOT);
            if (suffix.startsWith("*")) {
                suffix = suffix.substring(1);
            }
            if (!suffix.isEmpty() && !suffix.equals(".")) {
                out.add(suffix.startsWith(".") ? suffix.substring(1) : suffix);
            }
        }
        return List.copyOf(out);
    }

    /**
     * The host of each {@code host:port} - an IPv6 address in brackets as it
     * stands - lower case.
     */
    public static List<String> hostsOf(List<String> hostPorts) {
        List<String> hosts = new ArrayList<>();
        for (String one : hostPorts) {
            String entry = one.strip();
            int scheme = entry.indexOf("://");
            if (scheme >= 0) {
                entry = entry.substring(scheme + 3);
            }
            String host;
            if (entry.startsWith("[")) {
                int close = entry.indexOf(']');
                host = close > 0 ? entry.substring(1, close) : entry; // mutation-equivalent: the entry starts with [, so ] is never at 0
            } else {
                int colon = entry.lastIndexOf(':');
                host = colon > 0 ? entry.substring(0, colon) : entry;
            }
            if (!host.isEmpty()) {
                hosts.add(host.toLowerCase(Locale.ROOT));
            }
        }
        return List.copyOf(hosts);
    }
}
