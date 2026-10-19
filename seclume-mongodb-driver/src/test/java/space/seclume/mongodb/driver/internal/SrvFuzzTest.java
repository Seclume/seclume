package space.seclume.mongodb.driver.internal;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.mongodb.MongoConfigurationException;

/**
 * DNS answering a {@code mongodb+srv://} lookup with whatever it likes: the
 * URL that comes out names only hosts within the domain, each a plain host
 * name and port, and takes from the TXT record nothing but the three options
 * the specification allows - or the lookup is refused. Anything else would
 * let DNS send the login, and the credential with it, somewhere else.
 *
 * <p>Seeded; {@code -Dseclume.mongo.fuzz.rounds=N} runs more,
 * {@code -Dseclume.mongo.fuzz.seed=S} others.
 */
@Timeout(120)
class SrvFuzzTest {

    private static final int ROUNDS = Integer.getInteger("seclume.mongo.fuzz.rounds", 40_000);
    private static final String HOST = "cluster0.example.com";
    private static final String DOMAIN = ".example.com";
    private static final String PIECES = "abcz09-.:/?@,&=#%\\ \"'\t\n$_AZ";
    private static final List<String> SAFE_SRV = List.of("a.example.com:27017",
            "b.example.com.:27018", "shard-00.x.example.com:1");
    private static final List<String> SAFE_TXT = List.of("replicaSet=rs0&authSource=admin",
            "loadBalanced=false", "authSource=$external");
    private static final Set<String> TXT_KEYS = Set.of("authsource", "replicaset",
            "loadbalanced");

    @Test
    void dnsSendsTheLoginNowhereElse() {
        long seed = Long.getLong("seclume.mongo.fuzz.seed", 0x5A5);
        Random random = new Random(seed);
        Map<String, Integer> tally = new TreeMap<>();
        for (int round = 0; round < ROUNDS; round++) {
            List<String> srv = new ArrayList<>();
            int records = 1 + random.nextInt(3);
            for (int i = 0; i < records; i++) {
                srv.add(spoil(SAFE_SRV.get(random.nextInt(SAFE_SRV.size())), random));
            }
            List<String> txt = random.nextInt(4) == 0 ? List.of()
                    : List.of(spoil(SAFE_TXT.get(random.nextInt(SAFE_TXT.size())), random));
            Srv.Resolver resolver = new Srv.Resolver() {
                @Override
                public List<String> srv(String name) {
                    return srv;
                }

                @Override
                public List<String> txt(String name) {
                    return txt;
                }
            };
            String url;
            try {
                url = Srv.expand("mongodb+srv://app@" + HOST + "/orders?appName=x", resolver);
            } catch (MongoConfigurationException refused) {
                tally.merge("refused", 1, Integer::sum);
                continue;
            } catch (RuntimeException other) {
                fail("seed " + seed + " round " + round + " srv " + srv + " txt " + txt + ": " + other, other);
                return;
            }
            String why = check(url);
            if (why != null) {
                fail("seed " + seed + " round " + round + " srv " + srv + " txt " + txt + " -> " + url + ": " + why);
            }
            tally.merge("expanded", 1, Integer::sum);
        }
        System.err.println("[srv fuzz] " + ROUNDS + " rounds, " + tally);
        assertTrue(tally.getOrDefault("expanded", 0) > 0, "nothing ever got through");
        assertTrue(tally.getOrDefault("refused", 0) > 0, "nothing was ever refused");
    }

    /** Null when the URL is one DNS could rightly have made, else what is wrong with it. */
    private static String check(String url) {
        String rest = url.substring("mongodb://app@".length());
        int slash = rest.indexOf('/');
        if (!url.startsWith("mongodb://app@") || slash < 0) {
            return "not the shape asked for";
        }
        for (String seed : rest.substring(0, slash).split(",", -1)) {
            if (!seed.matches("[a-z0-9.-]+:[0-9]{1,5}")) {
                return "the seed '" + seed + "' is not a host name and port";
            }
            String name = seed.substring(0, seed.indexOf(':'));
            if (!name.endsWith(DOMAIN)) {
                return "the seed '" + seed + "' is outside " + DOMAIN.substring(1);
            }
        }
        String path = rest.substring(slash);
        if (!path.startsWith("/orders?")) {
            return "the database or query moved: " + path;
        }
        for (String pair : path.substring("/orders?".length()).split("&")) {
            String key = pair.substring(0, Math.max(0, pair.indexOf('='))).toLowerCase();
            if (!TXT_KEYS.contains(key) && !key.equals("appname") && !key.equals("tls")) {
                return "an option nobody asked for: " + pair;
            }
            if (key.equals("tls") && !pair.equals("tls=true")) {
                return "TLS changed: " + pair;
            }
            if (pair.contains("#") || pair.contains("/") || pair.contains("@")) {
                return "a value that ends the URL early: " + pair;
            }
        }
        return null;
    }

    private static String spoil(String record, Random random) {
        StringBuilder out = new StringBuilder(record);
        int edits = random.nextInt(4);
        for (int i = 0; i < edits; i++) {
            int at = out.isEmpty() ? 0 : random.nextInt(out.length() + 1);
            switch (random.nextInt(4)) {
                case 0 -> out.insert(at, PIECES.charAt(random.nextInt(PIECES.length())));
                case 1 -> {
                    if (at < out.length()) {
                        out.deleteCharAt(at);
                    }
                }
                case 2 -> {
                    String[] attacks = {"evil.com:27017/?x=", "@evil.com", ",evil.com:1",
                        "&tls=false", "&authMechanism=PLAIN", "#", "?", "%26tls%3Dfalse",
                        "x".repeat(70), ":0", ":99999", ":-1"};
                    out.insert(at, attacks[random.nextInt(attacks.length)]);
                }
                default -> {
                    if (at < out.length()) {
                        out.setCharAt(at, PIECES.charAt(random.nextInt(PIECES.length())));
                    }
                }
            }
        }
        return out.toString();
    }
}
