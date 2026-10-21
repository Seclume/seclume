package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Random;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Whatever a certificate's name and the host look like - DNS syntax or not,
 * Punycode, empty labels, dots at either end - matching answers without an
 * exception, and a wildcard never spans a public suffix or more than one
 * label. The fuzzer runs nightly; the seeded rounds run in every build.
 */
class HostnameMatchFuzzTest {

    /**
     * Suffixes from the list's ICANN section, the one {@link PublicSuffixes}
     * reads; the private section (github.io and the like) is registrable
     * there on purpose - see {@code PublicSuffixesTest}.
     */
    private static final String[] PUBLIC_SUFFIXES = {"co.uk", "com.au", "foo.ck",
        "foo.kawasaki.jp", "xn--55qx5d.cn"};
    private static final int ROUNDS = Integer.getInteger("seclume.hostname.fuzz.rounds", 20_000);

    @FuzzTest(maxDuration = "60s")
    void wildcardAndPunycodeBoundaries(FuzzedDataProvider data) {
        check(data.consumeString(256), data.consumeString(256), data.consumeString(256));
    }

    @Test
    void seededNamesAnswerAndNeverWidenAWildcard() {
        long seed = Long.getLong("seclume.hostname.fuzz.seed", 0x4057AA);
        Random random = new Random(seed);
        for (int round = 0; round < ROUNDS; round++) {
            String prefix = name(random);
            String pattern = name(random);
            String host = name(random);
            try {
                check(prefix, pattern, host);
            } catch (AssertionError | RuntimeException broken) {
                throw new AssertionError("seed " + seed + " round " + round + ": prefix '"
                        + prefix + "' pattern '" + pattern + "' host '" + host + "'", broken);
            }
        }
    }

    private static void check(String prefix, String pattern, String host) {
        // Invalid DNS syntax is a refusal, never an uncaught parser exception.
        HostnameMatch.matchesPattern(pattern, host);
        HostnameMatch.matchesPattern("*." + pattern, host);
        for (String suffix : PUBLIC_SUFFIXES) {
            assertFalse(HostnameMatch.matchesPattern("*." + suffix, prefix + "." + suffix),
                    "*." + suffix + " matched " + prefix + "." + suffix);
        }
        assertFalse(HostnameMatch.matchesPattern("*.example.com", prefix + ".a.b.example.com"));
    }

    /** Names from the characters that matter at the boundaries, valid and not. */
    private static String name(Random random) {
        String alphabet = "abcxyz019-.*_ ü公ß";
        String[] pieces = {"xn--", "xn--55qx5d", "co.uk", "kawasaki.jp", "..", ".", "*.", "-",
            "a", "www", "EXAMPLE", "公司"};
        StringBuilder name = new StringBuilder();
        int parts = random.nextInt(6);
        for (int i = 0; i < parts; i++) {
            if (random.nextBoolean()) {
                name.append(pieces[random.nextInt(pieces.length)]);
            } else {
                int length = 1 + random.nextInt(8);
                for (int j = 0; j < length; j++) {
                    name.append(alphabet.charAt(random.nextInt(alphabet.length())));
                }
            }
            if (random.nextInt(3) != 0) {
                name.append('.');
            }
        }
        return name.toString();
    }
}
