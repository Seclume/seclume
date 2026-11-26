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

    /** Whether {@code host} may be connected to - see {@link space.seclume.internal.SeedDomains}. */
    public static boolean mayJoin(String host, List<String> seeds, List<String> extra) {
        return space.seclume.internal.SeedDomains.admits(host, seeds, extra);
    }

    /** {@code a.example,*.b.example,.c.example} as suffixes, lower case, without the wildcard. */
    public static List<String> suffixes(String list) {
        return space.seclume.internal.SeedDomains.suffixes(list);
    }
}
