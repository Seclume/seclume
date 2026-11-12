package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.ValueLayout;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;

/**
 * How often a source of temporary credentials is asked, and what becomes of
 * the sets a request may still be on its way with.
 *
 * <p>A source can answer with a set that is already about to expire - the
 * instance metadata service hands out the old one until the next is there.
 * Asked again for every request, each answer was a new generation, and the
 * fourth request closed the credentials the first one had just been signed
 * with: its session token was gone before the request was written.
 */
class TemporaryCredentialsRefreshTest {

    /** A source that counts how often it is asked, with a clock a test moves. */
    private static final class Source extends TemporaryCredentials {
        private Instant now = Instant.parse("2026-11-12T08:00:00Z");
        private long validFor;
        private boolean unreachable;
        private int asked;
        private final List<SecretScope> handedOut = new ArrayList<>();

        Source(long validForSeconds) {
            this.validFor = validForSeconds;
        }

        @Override
        Instant now() {
            return now;
        }

        @Override
        Fetched fetch() {
            asked++;
            if (unreachable) {
                throw new SecretUnavailableException("the source could not be reached");
            }
            SecretScope key = secret("key-" + asked);
            SecretScope token = secret("token-" + asked);
            handedOut.add(key);
            handedOut.add(token);
            return new Fetched("ASIA" + asked, now.plusSeconds(validFor), key, token);
        }

        @Override
        String name() {
            return "test";
        }

        void later(long seconds) {
            now = now.plusSeconds(seconds);
        }

        private static SecretScope secret(String text) {
            SecretScope scope = SecretScope.allocate(32);
            for (int i = 0; i < text.length(); i++) {
                scope.segment().set(ValueLayout.JAVA_BYTE, i, (byte) text.charAt(i));
            }
            scope.length(text.length());
            return scope;
        }
    }

    private final List<Source> sources = new ArrayList<>();

    private Source source(long validForSeconds) {
        Source source = new Source(validForSeconds);
        sources.add(source);
        return source;
    }

    @AfterEach
    void wipe() {
        for (Source source : sources) {
            source.handedOut.forEach(SecretScope::close);
        }
    }

    @Test
    void aSetWithAnHourLeftIsFetchedOnce() {
        Source source = source(3600);
        TemporaryCredentials.Generation first = source.current();
        for (int i = 0; i < 10; i++) {
            source.later(60);
            assertSame(first, source.current());
        }
        assertEquals(1, source.asked);
    }

    @Test
    void fiveMinutesBeforeItsEndTheNextSetIsFetched() {
        Source source = source(3600);
        TemporaryCredentials.Generation first = source.current();
        source.later(3600 - 299);
        TemporaryCredentials.Generation second = source.current();
        assertNotSame(first, second);
        assertEquals("ASIA2", second.accessKeyId);
        assertEquals(2, source.asked);
    }

    @Test
    void aSetAlreadyNearItsEndIsNotFetchedAgainForEveryRequest() {
        Source source = source(60);                 // what the source has is nearly over
        TemporaryCredentials.Generation signedWith = source.current();
        for (int i = 0; i < 20; i++) {
            assertSame(signedWith, source.current());
        }
        assertEquals(1, source.asked, "one answer is lived with for a few seconds");
        // The request signed with the first set is written now: its token is there.
        assertNotNull(TemporaryCredentials.byPlaceholder(signedWith.placeholder));
        assertEquals(7, signedWith.token.length());
    }

    @Test
    void itIsAskedAgainAfterAFewSeconds() {
        Source source = source(60);
        TemporaryCredentials.Generation first = source.current();
        source.later(TemporaryCredentials.RETRY_SECONDS - 1);
        assertSame(first, source.current());
        source.later(1);
        source.validFor = 3600;                     // the next set is there now
        TemporaryCredentials.Generation second = source.current();
        assertNotSame(first, second);
        assertEquals(2, source.asked);
        source.later(600);
        assertSame(second, source.current());
        assertEquals(2, source.asked);
        // The one before stays for a request that is still on its way with it.
        assertSame(first, TemporaryCredentials.byPlaceholder(first.placeholder));
    }

    @Test
    void aSourceThatCannotBeReachedLeavesTheSetThatIsStillValid() {
        Source source = source(3600);
        TemporaryCredentials.Generation first = source.current();
        source.later(3600 - 200);                   // due, and valid for 200 seconds more
        source.unreachable = true;
        assertSame(first, source.current());
        assertSame(first, source.current());
        assertEquals(2, source.asked, "asked once, then left alone for a few seconds");
        source.later(TemporaryCredentials.RETRY_SECONDS);
        assertSame(first, source.current());
        assertEquals(3, source.asked);
        source.unreachable = false;
        source.later(TemporaryCredentials.RETRY_SECONDS);
        assertEquals("ASIA4", source.current().accessKeyId);
    }

    @Test
    void anExpiredSetIsNotUsedWhenTheSourceCannotBeReached() {
        Source source = source(3600);
        source.current();
        source.later(3601);
        source.unreachable = true;
        assertThrows(SecretUnavailableException.class, source::current);
        assertThrows(SecretUnavailableException.class, source::current);
        assertEquals(3, source.asked, "every request asks: there is nothing to live with");
    }

    @Test
    void withoutAnySetTheFailureIsTheCallers() {
        Source source = source(3600);
        source.unreachable = true;
        assertThrows(SecretUnavailableException.class, source::current);
        source.unreachable = false;
        assertEquals("ASIA2", source.current().accessKeyId);
    }
}
