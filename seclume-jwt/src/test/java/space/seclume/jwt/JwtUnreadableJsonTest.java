package space.seclume.jwt;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * exp, nbf and crit were looked up in a way that answered "absent" for a
 * payload that could not be read up to the field: an expired token whose
 * claims had a comma missing, or nested deeper than the reader goes, was
 * accepted - signed, but past its time.
 */
class JwtUnreadableJsonTest {

    private static final String KEY = "a-32-byte-hmac-key-for-hs256-ok!";

    private static SeclumeJwt jwt(Path dir) throws Exception {
        Path key = dir.resolve("hs");
        Files.writeString(key, KEY);
        SeclumeJwt jwt = SeclumeJwt.of("HS256?provider=file&path="
                + key.toString().replace('\\', '/'));
        jwt.clock(Clock.fixed(Instant.ofEpochSecond(1000), ZoneOffset.UTC));
        return jwt;
    }

    @Test
    void anExpiredTokenWithAMissingCommaIsRefused(@TempDir Path dir) throws Exception {
        try (SeclumeJwt jwt = jwt(dir)) {
            assertThrows(RuntimeException.class,
                    () -> jwt.verify(jwt.sign("{\"sub\":\"decoy\" \"exp\":990}")));
        }
    }

    @Test
    void aTokenNestedBeyondTheLimitIsRefused(@TempDir Path dir) throws Exception {
        try (SeclumeJwt jwt = jwt(dir)) {
            String nested = "[".repeat(600) + "]".repeat(600);
            assertThrows(RuntimeException.class,
                    () -> jwt.verify(jwt.sign("{\"x\":" + nested + ",\"exp\":990}")));
        }
    }

    @Test
    void aReadableTokenWithAFutureExpIsAccepted(@TempDir Path dir) throws Exception {
        try (SeclumeJwt jwt = jwt(dir)) {
            jwt.verify(jwt.sign("{\"sub\":\"decoy\",\"exp\":2000}"));
        }
    }
}
