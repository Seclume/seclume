package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

/**
 * The two things every message about a JDBC URL relies on, over thousands of
 * random URLs rather than a handful chosen by hand.
 *
 * <ul>
 * <li>{@link JdbcUrl#redact} leaves no password in what it returns - in any
 *     of the spellings vendors' URLs carry one: {@code ?password=},
 *     SQL Server's {@code ;password=} plain and in braces, {@code //user:password@},
 *     Oracle's {@code user/password@} plain and quoted, MySQL's key-value
 *     hosts - and keeps the scheme, so that the message still says what the
 *     URL was. It takes any string without failing.</li>
 * <li>{@link JdbcUrl#parse} takes any string to a result or to an
 *     {@link IllegalArgumentException}, never to another exception, and its
 *     message carries no password that was in the URL.</li>
 * </ul>
 *
 * <p>The passwords are upper case and the rest of each URL lower case, so
 * that a piece of a password found in the output is a leak and not a host
 * name that happens to look like one. Not only the whole password is looked
 * for: any five characters of it with three capitals among them, so that a
 * value cut in two at a {@code ;} it contains is found too.
 *
 * <p>Seeded: a failure names its round and replays with
 * {@code -Dseclume.url.seed=}. {@code -Dseclume.url.rounds=} runs longer.
 */
class JdbcUrlPropertyTest {

    private static final int ROUNDS = Integer.getInteger("seclume.url.rounds", 4_000);
    private static final long SEED = Long.getLong("seclume.url.seed", 20261108L);
    private static final String PREFIX = "jdbc:seclume:postgresql:";
    private static final String[] HOSTS = {"db", "primary.example", "10.0.0.7", "[::1]",
            "db-1.internal", "replica"};
    private static final String[] WORDS = {"app", "orders", "x", "tenant_a", "reporting"};
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /** A URL and the text of the password as it stands in it. */
    private record Case(String url, String secret) {
    }

    @Test
    void redactLeavesNoPasswordAndKeepsTheScheme() {
        List<Function<Random, Case>> families = List.of(
                JdbcUrlPropertyTest::query, JdbcUrlPropertyTest::sqlServer,
                JdbcUrlPropertyTest::sqlServerBraced, JdbcUrlPropertyTest::userInfo,
                JdbcUrlPropertyTest::oracle, JdbcUrlPropertyTest::oracleQuoted,
                JdbcUrlPropertyTest::mySqlKeyValue);
        Random random = new Random(SEED);
        for (int round = 0; round < ROUNDS; round++) {
            Case one = families.get(random.nextInt(families.size())).apply(random);
            try {
                String redacted = JdbcUrl.redact(one.url());
                assertNoPieceOf(one.secret(), redacted);
                String scheme = one.url().substring(0, one.url().indexOf(':', 5) + 1);
                assertTrue(redacted.startsWith(scheme), redacted);
            } catch (AssertionError | RuntimeException e) {
                throw new AssertionError("round " + round + " of seed " + SEED + ", url "
                        + one.url() + ": " + e, e);
            }
        }
    }

    @Test
    void redactTakesAnyString() {
        Random random = new Random(SEED + 1);
        for (int round = 0; round < ROUNDS; round++) {
            String text = garbage(random);
            try {
                String redacted = JdbcUrl.redact(text);
                assertTrue(redacted.length() <= text.length() + 1, redacted);
            } catch (RuntimeException e) {
                throw new AssertionError("round " + round + " of seed " + SEED + ", text "
                        + text + ": " + e, e);
            }
        }
    }

    @Test
    void parseEndsInAResultOrARefusalThatNamesNoPassword() {
        Random random = new Random(SEED + 2);
        int parsed = 0;
        int refused = 0;
        for (int round = 0; round < ROUNDS; round++) {
            Case one = seclumeUrl(random);
            try {
                JdbcUrl.Parsed result = JdbcUrl.parse(one.url(), new Properties(), PREFIX, 5432);
                assertFalse(result.host().contains("@"), "a login taken for a host: " + result.host());
                assertTrue(result.port() >= 1 && result.port() <= 65535, "port " + result.port());
                parsed++;
            } catch (IllegalArgumentException e) {
                try {
                    for (Throwable t = e; t != null; t = t.getCause()) {
                        assertNoPieceOf(one.secret(), String.valueOf(t.getMessage()));
                    }
                } catch (AssertionError leak) {
                    throw new AssertionError("round " + round + " of seed " + SEED + ", url "
                            + one.url() + ": " + leak.getMessage(), leak);
                }
                refused++;
            } catch (RuntimeException e) {
                throw new AssertionError("round " + round + " of seed " + SEED + ", url "
                        + one.url() + ": not a refusal but " + e, e);
            }
        }
        // Both outcomes have to be reached, or the generator tests one of them only.
        assertTrue(parsed > ROUNDS / 10 && refused > ROUNDS / 10, parsed + " parsed, "
                + refused + " refused");
    }

    @Test
    void theExamplesThatLeakedBefore() {
        // Found by the first run of this test, 08.11.2026: redact kept
        // everything before a '?', and parse took user:password@ for a host.
        assertEquals("jdbc:sqlserver://db:1433;user=?;password=?",
                JdbcUrl.redact("jdbc:sqlserver://db:1433;user=sa;password=HUNTER2"));
        assertEquals("jdbc:mysql://app:?@db/x", JdbcUrl.redact("jdbc:mysql://app:HUNTER2@db/x"));
        assertEquals("jdbc:oracle:thin:scott/?@db:1521/svc",
                JdbcUrl.redact("jdbc:oracle:thin:scott/HUNTER2@db:1521/svc"));
        assertEquals("jdbc:mysql://address=(host=?)(password=?)/x",
                JdbcUrl.redact("jdbc:mysql://address=(host=db)(password=HUNTER2)/x"));
        assertEquals("jdbc:seclume:postgresql://db:5432/app",
                JdbcUrl.redact("jdbc:seclume:postgresql://db:5432/app"));
        for (String url : List.of(PREFIX + "//app:HUNTER2@db/x", PREFIX + "//app:HUNTER2@db:5432/x")) {
            IllegalArgumentException e = org.junit.jupiter.api.Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> JdbcUrl.parse(url, new Properties(), PREFIX, 5432));
            assertFalse(e.getMessage().contains("HUNTER2"), e.getMessage());
            assertTrue(e.getMessage().contains("no user:password@"), e.getMessage());
        }
    }

    /** No five characters of {@code secret} with three capitals among them in {@code text}. */
    private static void assertNoPieceOf(String secret, String text) {
        assertFalse(text.contains(secret), "the password is in: " + text);
        for (int i = 0; i + 5 <= secret.length(); i++) {
            String piece = secret.substring(i, i + 5);
            if (piece.chars().filter(c -> c >= 'A' && c <= 'Z').count() >= 3) {
                assertFalse(text.contains(piece), "a piece of the password, " + piece + ", is in: "
                        + text);
            }
        }
    }

    /** Capitals and some of {@code specials}, eight to twenty characters, three capitals at least. */
    private static String secret(Random random, String specials) {
        int length = 8 + random.nextInt(13);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            boolean special = !specials.isEmpty() && i % 3 == 2 && random.nextBoolean();
            out.append(special ? specials.charAt(random.nextInt(specials.length()))
                    : UPPER.charAt(random.nextInt(UPPER.length())));
        }
        return out.toString();
    }

    private static String pick(Random random, String[] from) {
        return from[random.nextInt(from.length)];
    }

    private static String hostPort(Random random) {
        String host = pick(random, HOSTS);
        return random.nextBoolean() ? host : host + ":" + (1 + random.nextInt(65535));
    }

    /** {@code key=value} options in lower case, {@code sep} between them. */
    private static List<String> options(Random random) {
        List<String> options = new ArrayList<>();
        int count = random.nextInt(4);
        for (int i = 0; i < count; i++) {
            options.add(pick(random, WORDS) + "=" + pick(random, WORDS));
        }
        return options;
    }

    private static String joined(List<String> parts, String separator, int at, String inserted) {
        List<String> all = new ArrayList<>(parts);
        all.add(Math.min(at, all.size()), inserted);
        return String.join(separator, all);
    }

    private static Case query(Random random) {
        String secret = secret(random, "-_.~!*'()$,;:");
        String encoded = random.nextBoolean() ? secret
                : URLEncoder.encode(secret, StandardCharsets.UTF_8);
        String key = pick(random, new String[] {"password", "pwd", "secret", "token-value"});
        List<String> options = options(random);
        String scheme = pick(random, new String[] {"jdbc:postgresql:", "jdbc:mysql:", "jdbc:mariadb:",
                "jdbc:seclume:postgresql:"});
        return new Case(scheme + "//" + hostPort(random) + "/" + pick(random, WORDS) + "?"
                + joined(options, "&", random.nextInt(4), key + "=" + encoded), encoded);
    }

    private static Case sqlServer(Random random) {
        String secret = secret(random, "-_.~!*'$:/?@&");
        List<String> options = options(random);
        return new Case("jdbc:sqlserver://" + hostPort(random) + ";"
                + joined(options, ";", random.nextInt(4), "password=" + secret), secret);
    }

    private static Case sqlServerBraced(Random random) {
        String secret = secret(random, ";=,()&?@").replace("}", "");
        String braced = "{" + secret + (random.nextBoolean() ? "}}" + secret(random, ";") : "") + "}";
        List<String> options = options(random);
        return new Case("jdbc:sqlserver://" + hostPort(random) + ";"
                + joined(options, ";", random.nextInt(4), "password=" + braced), secret);
    }

    private static Case userInfo(Random random) {
        // What RFC 3986 allows in a userinfo, the reserved rest %-encoded.
        String secret = secret(random, "-._~!$&'()*+,;=:");
        if (random.nextInt(4) == 0) {
            secret = secret + "%40" + secret(random, "");
        }
        String scheme = pick(random, new String[] {"jdbc:mysql:", "jdbc:mariadb:", "mongodb:",
                "jdbc:seclume:mysql:"});
        String tail = random.nextBoolean() ? "" : "?" + String.join("&", options(random));
        return new Case(scheme + "//" + pick(random, WORDS) + ":" + secret + "@" + hostPort(random)
                + "/" + pick(random, WORDS) + tail, secret);
    }

    private static Case oracle(Random random) {
        String secret = secret(random, "_$#");
        String address = switch (random.nextInt(3)) {
            case 0 -> hostPort(random) + "/" + pick(random, WORDS);
            case 1 -> "//" + hostPort(random) + "/" + pick(random, WORDS);
            default -> "(description=(address=(protocol=tcp)(host=" + pick(random, HOSTS)
                    + ")(port=1521))(connect_data=(service_name=" + pick(random, WORDS) + ")))";
        };
        return new Case("jdbc:oracle:thin:" + pick(random, WORDS) + "/" + secret + "@" + address,
                secret);
    }

    private static Case oracleQuoted(Random random) {
        String secret = secret(random, "@/:;=()?!").replace("\"", "");
        return new Case("jdbc:oracle:thin:" + pick(random, WORDS) + "/\"" + secret + "\"@//"
                + hostPort(random) + "/" + pick(random, WORDS), secret);
    }

    private static Case mySqlKeyValue(Random random) {
        String secret = secret(random, "-_.~!*'$:/@&=");
        String host = pick(random, new String[] {"db", "10.0.0.7", "replica"});
        String url = random.nextBoolean()
                ? "jdbc:mysql://address=(host=" + host + ")(port=3306)(password=" + secret
                        + ")(user=" + pick(random, WORDS) + ")/" + pick(random, WORDS)
                : "jdbc:mysql://(host=" + host + ",password=" + secret + ",port=3306)/"
                        + pick(random, WORDS);
        return new Case(url, secret);
    }

    /**
     * A seclume URL as people write them, right or wrong: a login before the
     * host, hosts with and without ports, ports that are none, empty lists,
     * IPv6, options with and without values, broken %-encodings.
     */
    private static Case seclumeUrl(Random random) {
        String secret = secret(random, "-._~!$'()*+;=");
        StringBuilder url = new StringBuilder(PREFIX);
        if (random.nextInt(8) > 0) {
            url.append("//");
        }
        if (random.nextInt(4) == 0) {
            url.append(pick(random, WORDS));
            if (random.nextBoolean()) {
                url.append(':').append(secret);
            }
            url.append('@');
        }
        int hosts = random.nextInt(4);
        for (int i = 0; i < hosts; i++) {
            if (i > 0) {
                url.append(',');
            }
            url.append(switch (random.nextInt(6)) {
                case 0 -> pick(random, HOSTS) + ":" + (random.nextInt(70_000) - 2);
                case 1 -> pick(random, HOSTS) + ":" + pick(random, WORDS);
                case 2 -> pick(random, HOSTS) + ":";
                default -> hostPort(random);
            });
        }
        if (random.nextInt(5) > 0) {
            url.append('/').append(pick(random, WORDS));
        }
        if (random.nextBoolean()) {
            url.append('?');
            List<String> options = options(random);
            if (random.nextInt(3) == 0) {
                options.add(pick(random, new String[] {"targetServerType", "hostSelection"})
                        + "=" + pick(random, new String[] {"primary", "any", "ordered", "quality",
                        "best", ""}));
            }
            if (random.nextInt(6) == 0) {
                options.add(pick(random, WORDS) + "=%" + pick(random, new String[] {"", "4", "zz",
                        "41"}));
            }
            if (random.nextInt(3) == 0) {
                options.add("password=" + secret);
            }
            url.append(String.join("&", options));
        }
        return new Case(url.toString(), secret);
    }

    /** Any string of the characters URLs are taken apart at, and some others. */
    private static String garbage(Random random) {
        String alphabet = ":/@?&=;,(){}\"%[]#AZaz09 é中";
        StringBuilder out = new StringBuilder();
        int length = random.nextInt(60);
        for (int i = 0; i < length; i++) {
            out.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return out.toString();
    }
}
