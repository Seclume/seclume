import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.crac.Context;
import org.crac.Core;
import org.crac.Resource;

/**
 * A checkpoint slower than seclume's hold: a resource registered before
 * seclume is notified after it, and takes longer than seclume.crac.holdMillis.
 * Meanwhile a thread asks for a new secret again and again. None may be let
 * through before the restore - the image is not written yet.
 *
 * Run with -Dseclume.crac.holdMillis=1000; the slow resource takes 3 s.
 * Prints PROOF lines after the restore: each attempt, and whether one went
 * through while the checkpoint was still running.
 */
public class CracHoldProof {

    static final List<String> LOG = new CopyOnWriteArrayList<>();
    static volatile boolean checkpointRunning;
    static volatile boolean madeDuringCheckpoint;

    public static void main(String[] args) throws Exception {
        Resource slow = new Resource() {
            @Override
            public void beforeCheckpoint(Context<? extends Resource> context) throws Exception {
                checkpointRunning = true;
                Thread asker = new Thread(CracHoldProof::ask, "asker");
                asker.setDaemon(true);
                asker.start();
                Thread.sleep(3000);
            }

            @Override
            public void afterRestore(Context<? extends Resource> context) {
                checkpointRunning = false;
            }
        };
        Core.getGlobalContext().register(slow);          // before seclume: notified after it
        space.seclume.crac.SeclumeCrac.registerProcess();
        Core.checkpointRestore();
        Thread.sleep(500);
        for (String line : LOG) {
            System.out.println("PROOF " + line);
        }
        System.out.println("PROOF made during the checkpoint: " + madeDuringCheckpoint);
    }

    static void ask() {
        for (int i = 0; i < 4; i++) {
            long start = System.nanoTime();
            try {
                space.seclume.internal.Checkpoint.awaitOpen();
                boolean during = checkpointRunning;
                madeDuringCheckpoint |= during;
                LOG.add("attempt " + i + " let through after " + (System.nanoTime() - start) / 1_000_000
                        + " ms, checkpoint running: " + during);
                return;
            } catch (IllegalStateException refused) {
                LOG.add("attempt " + i + " refused after " + (System.nanoTime() - start) / 1_000_000
                        + " ms");
            }
        }
    }
}
