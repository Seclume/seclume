package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Where a lane's work runs, and that it still runs one task after the other.
 */
@Timeout(60)
class LaneTest {

    private static final Duration WAIT = Duration.ofSeconds(30);

    @Test
    void aLanesWorkRunsOnAPlatformThreadOfTheDriver() {
        try (Lane lane = new Lane()) {
            Thread ran = lane.call(Thread::currentThread).block(WAIT);
            assertFalse(ran.isVirtual(), "a lane with work and a free platform thread blocks in "
                    + "the kernel, not on a carrier: " + ran);
            assertTrue(ran.getName().startsWith("seclume-r2dbc-"), ran.getName());
            assertTrue(ran.isDaemon(), "a lane's thread must not keep the JVM alive");
        }
    }

    private static final InheritableThreadLocal<String> TENANT = new InheritableThreadLocal<>();

    /**
     * A thread the driver starts for one subscriber's task serves the ones
     * after it: an InheritableThreadLocal of the first - a tenant, a
     * principal - became theirs. The driver's threads inherit none.
     */
    @Test
    void aLanesThreadsInheritNothingOfTheCaller() {
        TENANT.set("tenant-a");
        try (Lane lane = new Lane()) {
            org.junit.jupiter.api.Assertions.assertNull(lane.call(TENANT::get).block(WAIT),
                    "the lane's work saw the caller's thread local");
            org.junit.jupiter.api.Assertions.assertNull(lane.callWaiting(TENANT::get).block(WAIT),
                    "the borrow saw the caller's thread local");
        } finally {
            TENANT.remove();
        }
    }

    @Test
    void theBorrowWaitsOnAVirtualThread() {
        try (Lane lane = new Lane()) {
            Thread ran = lane.callWaiting(Thread::currentThread).block(WAIT);
            assertTrue(ran.isVirtual(), "a borrow may wait for a full pool, and must not hold a "
                    + "platform thread while it does: " + ran);
        }
    }

    @Test
    void tasksOfOneLaneRunInOrderAndOneAtATime() {
        try (Lane lane = new Lane()) {
            List<Integer> order = Collections.synchronizedList(new ArrayList<>());
            int[] running = new int[1];
            boolean[] overlapped = new boolean[1];
            Flux.range(0, 200)
                    .flatMap(i -> lane.call(() -> {
                        synchronized (running) {
                            if (++running[0] > 1) {
                                overlapped[0] = true;
                            }
                        }
                        order.add(i);
                        synchronized (running) {
                            running[0]--;
                        }
                        return i;
                    }), 64)
                    .blockLast(WAIT);
            assertFalse(overlapped[0], "two tasks of one connection ran at once");
            assertEquals(200, order.size());
            for (int i = 0; i < order.size(); i++) {
                assertEquals(i, order.get(i), "tasks ran out of the order they were subscribed in");
            }
        }
    }

    /**
     * More lanes busy at once than there are platform threads: the ones that
     * find none run on a virtual thread at once instead of waiting.
     */
    @Test
    void lanesPastTheBoundRunOnVirtualThreadsWithoutWaiting() throws Exception {
        int lanes = Lane.PLATFORM_THREADS + 8;
        CountDownLatch allStarted = new CountDownLatch(lanes);
        CountDownLatch release = new CountDownLatch(1);
        List<Lane> open = new ArrayList<>();
        List<Mono<Thread>> calls = new ArrayList<>();
        try {
            for (int i = 0; i < lanes; i++) {
                Lane lane = new Lane();
                open.add(lane);
                calls.add(lane.call(() -> {
                    allStarted.countDown();
                    release.await(30, TimeUnit.SECONDS);
                    return Thread.currentThread();
                }));
            }
            Mono<List<Thread>> all = Flux.merge(calls).collectList().cache();
            all.subscribe();
            assertTrue(allStarted.await(30, TimeUnit.SECONDS),
                    "a lane waited for another lane's thread");
            release.countDown();
            List<Thread> threads = all.block(WAIT);
            assertEquals(lanes, threads.size());
            assertTrue(threads.stream().anyMatch(Thread::isVirtual),
                    "past the bound a lane runs on a virtual thread");
            assertTrue(threads.stream().filter(t -> !t.isVirtual()).count() <= Lane.PLATFORM_THREADS,
                    "more platform threads than the bound");
        } finally {
            release.countDown();
            open.forEach(Lane::close);
        }
    }
}
