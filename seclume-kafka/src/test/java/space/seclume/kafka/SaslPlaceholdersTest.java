package space.seclume.kafka;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretScope;

/**
 * Two placeholders share nothing but the prefix: they were a process nonce and
 * a count, so one seen in a log named every one after it. Each is 16 random
 * bytes now.
 */
class SaslPlaceholdersTest {

    @Test
    void twoPlaceholdersAreUnrelated() {
        String prefix = new String(SaslPlaceholders.PREFIX, java.nio.charset.StandardCharsets.US_ASCII);
        try (SecretScope one = SecretScope.allocate(4); SecretScope two = SecretScope.allocate(4)) {
            String a = SaslPlaceholders.register(one).substring(prefix.length());
            String b = SaslPlaceholders.register(two).substring(prefix.length());
            assertEquals(32, a.length(), a);
            assertEquals(32, b.length(), b);
            int same = 0;
            while (same < a.length() && a.charAt(same) == b.charAt(same)) {
                same++;
            }
            assertTrue(same < 8, "the two placeholders begin alike: " + a + ", " + b);
            assertTrue(!a.contains("-"), "a count is still in it: " + a);
            SaslPlaceholders.take(prefix + a);
            SaslPlaceholders.take(prefix + b);
        }
    }
}
