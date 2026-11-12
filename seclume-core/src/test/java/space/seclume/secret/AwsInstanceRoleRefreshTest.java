package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * How often a workload's credentials source is asked. Kept until five minutes
 * before they expire - and a source that answers with credentials already
 * inside those five minutes was asked again for every single use, a round trip
 * to the metadata service each time, under the lock every user waits for.
 */
class AwsInstanceRoleRefreshTest {

    /** A clock a test moves. */
    private static final class Moving extends Clock {
        private Instant now = Instant.parse("2026-11-12T08:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        void later(long seconds) {
            now = now.plusSeconds(seconds);
        }
    }

    private final Moving clock = new Moving();
    private long validFor = 3600;
    private boolean unreachable;
    private int asked;
    private final AwsInstanceRole role = new AwsInstanceRole(() -> {
        asked++;
        if (unreachable) {
            throw new SecretUnavailableException("the metadata service could not be reached");
        }
        return new AwsInstanceRole.Fetched("ASIA" + asked, clock.instant().plusSeconds(validFor),
                secret("key-" + asked), secret("token-" + asked));
    }, clock);

    @AfterEach
    void wipe() {
        role.close();
    }

    private static SecretScope secret(String text) {
        SecretScope scope = SecretScope.allocate(32);
        for (int i = 0; i < text.length(); i++) {
            scope.segment().set(ValueLayout.JAVA_BYTE, i, (byte) text.charAt(i));
        }
        scope.length(text.length());
        return scope;
    }

    /** The access key id and the secret key the role hands out now - test values, no secrets. */
    private String current() {
        return role.use((id, key, token) -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment out = arena.allocate(32);
                int length = key.writeSecret(out);
                StringBuilder text = new StringBuilder(id).append('/');
                for (int i = 0; i < length; i++) {
                    text.append((char) out.get(ValueLayout.JAVA_BYTE, i));
                }
                return text.toString();
            }
        });
    }

    @Test
    void credentialsWithAnHourLeftAreFetchedOnce() {
        for (int i = 0; i < 10; i++) {
            assertEquals("ASIA1/key-1", current());
            clock.later(60);
        }
        assertEquals(1, asked);
    }

    @Test
    void fiveMinutesBeforeTheirEndTheNextAreFetched() {
        assertEquals("ASIA1/key-1", current());
        clock.later(3600 - 299);
        assertEquals("ASIA2/key-2", current());
        assertEquals(2, asked);
        assertEquals(clock.instant().plusSeconds(3600), role.validUntil());
    }

    @Test
    void credentialsAlreadyNearTheirEndAreNotFetchedForEveryUse() {
        validFor = 60;                              // what the source has is nearly over
        for (int i = 0; i < 20; i++) {
            assertEquals("ASIA1/key-1", current());
        }
        assertEquals(1, asked, "one answer is lived with for a few seconds");
        clock.later(AwsInstanceRole.RETRY_SECONDS);
        validFor = 3600;                            // the next ones are there now
        assertEquals("ASIA2/key-2", current());
        clock.later(600);
        assertEquals("ASIA2/key-2", current());
        assertEquals(2, asked);
    }

    @Test
    void aSourceThatCannotBeReachedLeavesWhatIsStillValid() {
        assertEquals("ASIA1/key-1", current());
        clock.later(3600 - 200);                    // due, and valid for 200 seconds more
        unreachable = true;
        assertEquals("ASIA1/key-1", current());
        assertEquals("ASIA1/key-1", current());
        assertEquals(2, asked, "asked once, then left alone for a few seconds");
        clock.later(AwsInstanceRole.RETRY_SECONDS);
        assertEquals("ASIA1/key-1", current());
        assertEquals(3, asked);
        unreachable = false;
        clock.later(AwsInstanceRole.RETRY_SECONDS);
        assertEquals("ASIA4/key-4", current());
    }

    @Test
    void expiredCredentialsAreNotUsedWhenTheSourceCannotBeReached() {
        assertEquals("ASIA1/key-1", current());
        clock.later(3601);
        unreachable = true;
        assertThrows(SecretUnavailableException.class, this::current);
        assertThrows(SecretUnavailableException.class, this::current);
        assertEquals(3, asked, "every use asks: there is nothing to live with");
        unreachable = false;
        assertEquals("ASIA4/key-4", current());
    }

    @Test
    void afterTheyWereWipedTheyAreFetchedAtOnce() {
        validFor = 60;
        assertEquals("ASIA1/key-1", current());
        role.close();                               // a checkpoint drops them
        assertEquals("ASIA2/key-2", current());
        assertEquals(2, asked);
    }
}
