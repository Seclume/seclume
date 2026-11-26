package space.seclume.mongodb.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.mongodb.ConnectionString;
import com.mongodb.ServerAddress;

/**
 * Which hosts of a deployment get a connection - and the SCRAM proof, the
 * AWS signature or the OIDC token with it.
 *
 * <p>A hello names the members of a replica set, and a driver connects to
 * every one of them. One compromised member, or an {@code rs.reconfig},
 * could bring in a host of its choosing with a valid public certificate.
 * So a host may be one of the seeds, on any port; a host in a seed's parent
 * domain ({@code a.db.example} admits {@code b.db.example}); or a host under
 * a suffix named in {@code -Dseclume.mongodb.allowedHosts=a.example,b.example}.
 * Nothing else.
 *
 * <p>Public for seclume's own MongoDB driver, which applies the same rule to
 * its topology; not an API.
 */
public final class MemberHosts {

    /** Further host suffixes members may have: {@code -Dseclume.mongodb.allowedHosts=...}. */
    public static final List<String> EXTRA_ALLOWED = suffixes(
            System.getProperty("seclume.mongodb.allowedHosts", ""));

    private MemberHosts() {
    }

    /** The seeds' hosts of a connection string, lower case - for SRV the SRV name. */
    public static List<String> seedsOf(String connectionString) {
        List<String> seeds = new ArrayList<>();
        for (String host : new ConnectionString(connectionString).getHosts()) {
            seeds.add(new ServerAddress(host).getHost().toLowerCase(Locale.ROOT));
        }
        return List.copyOf(seeds);
    }

    /** Whether {@code host} may be connected to, given the seeds and the extra suffixes. */
    public static boolean mayJoin(String host, List<String> seeds, List<String> extra) {
        String name = host.toLowerCase(Locale.ROOT);
        for (String seed : seeds) {
            if (name.equals(seed)) {
                return true;
            }
            int dot = seed.indexOf('.');
            boolean literal = seed.chars().allMatch(ch -> ch == '.' || ch == ':'
                    || Character.digit(ch, 16) >= 0) || seed.startsWith("[");
            if (!literal && dot > 0 && seed.indexOf('.', dot + 1) > 0
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
        for (String one : list.split(",")) {
            String suffix = one.strip().toLowerCase(Locale.ROOT);
            if (suffix.startsWith("*")) {
                suffix = suffix.substring(1);       // *.b.example, as one would write it
            }
            if (!suffix.isEmpty() && !suffix.equals(".")) {
                out.add(suffix.startsWith(".") ? suffix.substring(1) : suffix);
            }
        }
        return List.copyOf(out);
    }
}
