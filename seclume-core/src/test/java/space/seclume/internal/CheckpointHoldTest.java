package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A checkpoint that takes longer than the hold - a slow resource notified
 * after seclume's, the image still being written - must not have secrets made
 * then: they would be in the image. The hold used to end by itself after
 * 60 s; now the waiting secret is refused and the hold stays until the
 * restore or the abort. seclume.crac.holdExpiry=release is the opt-out.
 */
class CheckpointHoldTest {

    @AfterEach
    void release() {
        Checkpoint.release();
    }

    @Test
    void anExpiredHoldRefusesTheSecretAndStays() {
        Checkpoint.hold();
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> Checkpoint.awaitOpen(50, false));
        assertTrue(refused.getMessage().contains("restore has not come"), refused.getMessage());
        assertTrue(Checkpoint.holding(), "the hold ended with the wait");
        assertThrows(IllegalStateException.class, () -> Checkpoint.awaitOpen(50, false),
                "a second secret was made while the checkpoint still holds");
    }

    @Test
    void theRestoreLetsTheWaitingSecretThrough() throws Exception {
        Checkpoint.hold();
        Thread restore = new Thread(() -> {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Checkpoint.release();
        });
        restore.start();
        Checkpoint.awaitOpen(10_000, false);
        assertFalse(Checkpoint.holding());
        restore.join();
    }

    @Test
    void theOptOutReleasesOnExpiry() {
        Checkpoint.hold();
        Checkpoint.awaitOpen(50, true);
        assertFalse(Checkpoint.holding(), "the opt-out did not release");
    }
}
