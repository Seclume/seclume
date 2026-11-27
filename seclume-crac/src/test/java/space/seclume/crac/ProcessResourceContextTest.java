package space.seclume.crac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.crac.CheckpointException;
import org.crac.Context;
import org.crac.Resource;
import org.crac.RestoreException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.OpenSslRandom;
import space.seclume.internal.Checkpoint;
import space.seclume.secret.SecretScope;

/**
 * The process resource as a CRaC runtime drives it: through a Context's
 * beforeCheckpoint and afterRestore, not by calling seclume's methods. The
 * context here does what the JDK's does - each resource in turn before the
 * checkpoint, in reverse after the restore, a failure collected into a
 * CheckpointException that aborts it.
 */
@Timeout(60)
@Isolated
class ProcessResourceContextTest {

    /** A context as the JDK's global one behaves. */
    private static final class Runtime extends Context<Resource> {
        private final List<Resource> resources = new ArrayList<>();

        @Override
        public void register(Resource resource) {
            resources.add(resource);
        }

        @Override
        public void beforeCheckpoint(Context<? extends Resource> context)
                throws CheckpointException {
            CheckpointException failed = null;
            for (Resource resource : resources) {
                try {
                    resource.beforeCheckpoint(this);
                } catch (Exception e) {
                    failed = failed == null ? new CheckpointException() : failed;
                    failed.addSuppressed(e);
                }
            }
            if (failed != null) {
                throw failed;
            }
        }

        @Override
        public void afterRestore(Context<? extends Resource> context) throws RestoreException {
            for (int i = resources.size() - 1; i >= 0; i--) {
                try {
                    resources.get(i).afterRestore(this);
                } catch (Exception e) {
                    RestoreException failed = new RestoreException();
                    failed.addSuppressed(e);
                    throw failed;
                }
            }
        }
    }

    private static Resource processResource() throws Exception {
        java.lang.reflect.Field field = SeclumeCrac.class.getDeclaredField("PROCESS");
        field.setAccessible(true);
        return (Resource) field.get(null);
    }

    @Test
    void aCheckpointHoldsNewSecretsAndTheRestoreReseedsBeforeReleasing() throws Exception {
        Runtime runtime = new Runtime();
        runtime.register(processResource());
        runtime.beforeCheckpoint(null);
        long before = OpenSslRandom.reseedsRequested();
        assertTrue(Checkpoint.holding() || !SeclumeCrac.HOLD_SECRETS,
                "nothing holds new secrets between the barrier and the image");
        try {
            runtime.afterRestore(null);
        } catch (RestoreException reseedRefused) {
            // OpenSSL there and refusing: the restore reports it - released regardless
        }
        assertEquals(before + 1, OpenSslRandom.reseedsRequested(),
                "the restore did not ask for a reseed");
        assertFalse(Checkpoint.holding(), "the restore did not let secrets through again");
    }

    @Test
    void anOpenSecretAbortsTheCheckpointThroughTheContext() throws Exception {
        Runtime runtime = new Runtime();
        runtime.register(processResource());
        try (SecretScope open = SecretScope.allocate(16)) {
            assertTrue(open.segment().byteSize() >= 16);
            CheckpointException aborted = assertThrows(CheckpointException.class,
                    () -> runtime.beforeCheckpoint(null));
            assertTrue(aborted.getSuppressed().length == 1
                    && aborted.getSuppressed()[0] instanceof IllegalStateException,
                    "the refusal did not reach the runtime as the reason");
        }
        assertFalse(Checkpoint.holding(), "an aborted checkpoint holds nothing");
    }
}
