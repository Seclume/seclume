package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * The login budget's task was only cancelled when the login finished: one
 * already running closed the connection the driver had just been handed. Now
 * whoever takes the budget off first decides - and a login that took it off
 * keeps its connection, however the two meet.
 */
class LoginBudgetRaceTest {

    /** A transport that only counts how often it was closed. */
    private static final class Counted implements Transport {
        final AtomicInteger closed = new AtomicInteger();

        @Override
        public int read(ByteBuffer into) {
            return -1;
        }

        @Override
        public int write(ByteBuffer from) {
            return 0;
        }

        @Override
        public boolean isOpen() {
            return closed.get() == 0;
        }

        @Override
        public void close() {
            closed.incrementAndGet();
        }
    }

    @Test
    void aLoginThatTookTheBudgetOffKeepsItsConnection() throws Exception {
        int liftedClosed = 0;
        int lifted = 0;
        int lost = 0;
        Counted[] all = new Counted[3_000];
        boolean[] won = new boolean[all.length];
        for (int i = 0; i < all.length; i++) {
            Counted transport = new Counted();
            all[i] = transport;
            Transports.watch(transport, i % 3);          // 0 to 2 ms: the two meet
            long until = System.nanoTime() + TimeUnit.MICROSECONDS.toNanos(i % 600);
            while (System.nanoTime() < until) {
                Thread.onSpinWait();
            }
            won[i] = Transports.lift(transport);
        }
        Thread.sleep(50);                                // what was still running has run
        for (int i = 0; i < all.length; i++) {
            if (won[i]) {
                lifted++;
                liftedClosed += all[i].closed.get();
            } else {
                lost++;
                assertEquals(1, all[i].closed.get(), "a budget that won closed once");
            }
        }
        assertEquals(0, liftedClosed, "a connection whose login took the budget off was closed");
        assertTrue(lifted > 0 && lost > 0, "the race did not happen both ways: lifted "
                + lifted + ", lost " + lost);
    }
}
