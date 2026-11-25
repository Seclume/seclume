package space.seclume.crac;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.Checkpoint;
import space.seclume.secret.SecretScope;

/**
 * The process's part of a checkpoint - wiping, waiting for open secrets,
 * holding new ones, reseeding OpenSSL after the restore - ran only inside a
 * pool's resource. An application that used seclume for TLS without a seclume
 * pool got none of it, and every clone of its image drew the same random TLS
 * key shares. It is a resource of its own now, registered with the class.
 */
@Timeout(60)
@Isolated
class ProcessQuiesceTest {

    @Test
    void withoutAPoolAnOpenSecretRefusesTheCheckpoint() {
        try (SecretScope open = SecretScope.allocate(16)) {
            assertTrue(open.segment().byteSize() >= 16);
            IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> SeclumeCrac.quiesceProcess(200));
            // The count alone named nobody (#58): where the secret came from, or how to find out.
            assertTrue(refused.getMessage().contains("seclume.debug.scopes")
                    || refused.getMessage().contains("opened at"), refused.getMessage());
        }
        assertFalse(Checkpoint.holding(), "a refused checkpoint holds nothing");
    }

    @Test
    void aQuietProcessIsHeldUntilTheRestoreAndReleasedAfter() throws Exception {
        SeclumeCrac.quiesceProcess(2000);
        try {
            assertTrue(Checkpoint.holding() || !SeclumeCrac.HOLD_SECRETS,
                    "no new secret may be made between the barrier and the image");
        } finally {
            try {
                SeclumeCrac.restoredProcess();
            } catch (IllegalStateException noOpenSsl) {
                // a JVM without OpenSSL 3 cannot reseed; the hold is released regardless
            }
        }
        assertFalse(Checkpoint.holding(), "the restore lets secrets through again");
    }

    @Test
    void theProcessPartIsRegisteredWithoutAnyPool() {
        SeclumeCrac.registerProcess();
        assertTrue(SeclumeCrac.processRegistered(),
                "nothing reseeds OpenSSL for an application without a pool");
    }
}
