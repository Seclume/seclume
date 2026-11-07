package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * How long a client-credentials token is kept: what {@code expires_in} says
 * - a number as RFC 6749 has it, or a string as older Entra ID sends it -
 * five minutes without it, at least a second, and at most a day: an
 * {@code expires_in} near 2^63 / 10^9 used to wrap the renewal time.
 */
class OAuthLifetimeTest {

    private static long lifetime(String json) {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        return OAuthToken.lifetime(MemorySegment.ofArray(bytes), bytes.length);
    }

    @Test
    void theAnnouncedLifetimeAsNumberOrString() {
        assertEquals(3599, lifetime("{\"expires_in\":3599}"));
        assertEquals(3599, lifetime("{\"expires_in\":\"3599\"}"));
    }

    @Test
    void withoutOneOrWithNonsenseFiveMinutes() {
        assertEquals(300, lifetime("{\"access_token\":\"x\"}"));
        assertEquals(300, lifetime("{\"expires_in\":\"soon\"}"));
        assertEquals(300, lifetime("{\"expires_in\":null}"));
    }

    @Test
    void atLeastASecond() {
        assertEquals(1, lifetime("{\"expires_in\":0}"));
        assertEquals(1, lifetime("{\"expires_in\":-50}"));
        assertEquals(1, lifetime("{\"expires_in\":\"-50\"}"));
    }

    @Test
    void atMostADay() {
        assertEquals(86_400, lifetime("{\"expires_in\":86400}"));
        assertEquals(86_400, lifetime("{\"expires_in\":86401}"));
        assertEquals(86_400, lifetime("{\"expires_in\":31536000}"));         // a year
        assertEquals(86_400, lifetime("{\"expires_in\":9223372036}"));        // 2^63 ns
        assertEquals(86_400, lifetime("{\"expires_in\":\"9223372036854775807\"}"));
        assertEquals(OAuthToken.MAX_LIFETIME_SECONDS, 86_400);
    }
}
