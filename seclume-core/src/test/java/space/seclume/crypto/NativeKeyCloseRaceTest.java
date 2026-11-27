package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Timeout;

/**
 * A native key closed while another thread derives with it: OpenSSL's or
 * CNG's key was freed under the running call - a use after free in native
 * code, a crash at best. The backends now let a close wait for the calls in
 * flight, and refuse every call after it. Misuse - NativeEcdh is meant to be
 * confined to one thread - but misuse must not reach freed memory.
 */
@Timeout(60)
class NativeKeyCloseRaceTest {

    @RepeatedTest(20)
    void aKeyClosedUnderRunningDerivationsIsNeitherUsedAfterFreeNorUsedAgain() throws Exception {
        NativeEcdh.Group group = NativeEcdh.Group.of(0x0018);       // secp384r1: OpenSSL or CNG
        NativeEcdh key;
        NativeEcdh peer;
        try {
            key = NativeEcdh.generate(group);
            peer = NativeEcdh.generate(group);
        } catch (RuntimeException | UnsatisfiedLinkError unavailable) {
            Assumptions.abort("no native P-384 here: " + unavailable);
            return;
        }
        MemorySegment peerPublic = Arena.global().allocate(group.publicSize());
        peer.publicKey(peerPublic);
        peer.close();
        AtomicReference<Throwable> wrong = new AtomicReference<>();
        AtomicBoolean stop = new AtomicBoolean();
        CountDownLatch going = new CountDownLatch(3);
        Thread[] threads = new Thread[3];
        for (int t = 0; t < threads.length; t++) {
            threads[t] = new Thread(() -> {
                going.countDown();
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment out = arena.allocate(group.secretSize());
                    while (!stop.get()) {
                        try {
                            key.derive(peerPublic, out);
                        } catch (IllegalStateException closed) {
                            return;                      // refused after close: as it should
                        }
                    }
                } catch (Throwable t2) {
                    wrong.compareAndSet(null, t2);
                }
            });
            threads[t].start();
        }
        going.await();
        Thread.sleep(5);
        key.close();
        stop.set(true);
        for (Thread thread : threads) {
            thread.join();
        }
        assertNull(wrong.get(), String.valueOf(wrong.get()));
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(group.secretSize());
            assertThrows(IllegalStateException.class, () -> key.derive(peerPublic, out));
        }
    }
}
