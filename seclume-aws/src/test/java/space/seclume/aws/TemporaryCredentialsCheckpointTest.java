package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.Checkpoint;
import space.seclume.secret.SecretScope;

/**
 * Before a CRaC or SnapStart checkpoint every secret this library holds is
 * wiped, so that none is in the image. AWS's temporary credentials - the
 * secret key and the session token - were not: the image carried them. They
 * are wiped now, and the next request fetches a fresh set.
 */
@Isolated
class TemporaryCredentialsCheckpointTest {

    private static SecretScope decoy(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        SecretScope scope = SecretScope.allocate(bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            scope.segment().set(ValueLayout.JAVA_BYTE, i, bytes[i]);
        }
        scope.length(bytes.length);
        return scope;
    }

    private static final class Counting extends TemporaryCredentials {
        final AtomicInteger fetches = new AtomicInteger();

        @Override
        Fetched fetch() {
            fetches.incrementAndGet();
            return new Fetched("ASIADECOY", Instant.now().plusSeconds(3600),
                    decoy("decoy-secret-key-" + fetches.get()),
                    decoy("decoy-session-token-" + fetches.get()));
        }

        @Override
        String name() {
            return "test";
        }
    }

    @Test
    void aCheckpointWipesTheCredentialsAndTheNextRequestFetchesAgain() {
        Counting credentials = new Counting();
        TemporaryCredentials.Generation before = credentials.current();
        assertEquals(1, credentials.fetches.get());
        Checkpoint.wipeAll();
        assertThrows(IllegalStateException.class,
                () -> before.secretKey.segment().get(ValueLayout.JAVA_BYTE, 0),
                "the secret key survived the checkpoint");
        assertThrows(IllegalStateException.class,
                () -> before.token.segment().get(ValueLayout.JAVA_BYTE, 0),
                "the session token survived the checkpoint");
        TemporaryCredentials.Generation after = credentials.current();
        assertNotSame(before, after);
        assertEquals(2, credentials.fetches.get(), "fetched again after the restore");
    }
}
